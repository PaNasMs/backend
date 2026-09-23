package worker

import (
	"context"
	"encoding/json"
	"os"

	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/accounts"
	"panasms.local/backend/internal/systemops/host"
	"panasms.local/backend/internal/systemops/webaccess"
)

type Dispatcher struct {
	Authorize func(string) (auth.Identity, error)
	Changing  func() (bool, error)
	Query     func(context.Context, string, string, string) (json.RawMessage, error)
	Plan      func(context.Context, string, map[string]any, string) (json.RawMessage, error)
	Execute   func(context.Context, string, map[string]any, *systemops.Reporter) (json.RawMessage, error)
	Recover   func(context.Context, *systemops.Request) (json.RawMessage, error)
}

func New() Dispatcher {
	return Dispatcher{Authorize: accounts.Authorize, Changing: changing, Query: query, Plan: plan, Execute: execute, Recover: recoverOperation}
}

func deny(message string) error { return &systemops.Rejected{Message: message} }

func (d Dispatcher) Handle(mode systemops.Mode, user string, req *systemops.Request, r *systemops.Reporter) (result json.RawMessage, err error) {
	mutated := false
	defer func() {
		if err != nil && !mutated {
			err = systemops.BeforeMutation(err)
		}
	}()
	id, err := d.Authorize(user)
	if err != nil {
		return nil, err
	}
	if req.Actor != nil && (id.UID != req.Actor.UID || id.Principal != req.Actor.Principal || id.Epoch != req.Actor.Epoch) {
		return nil, deny("Account identity or access has changed; request a new operation plan")
	}
	if id.Role != "admin" {
		if mode == systemops.ModeQuery {
			if req.View != "account-sessions" && req.View != "account-details" {
				return nil, deny("Administrator permissions required")
			}
			req.Target = user
		} else if req.Action != "user.session.end" || req.Params["target"] != user {
			return nil, deny("Administrator permissions required")
		}
	}
	if mode == systemops.ModeQuery {
		return d.Query(context.Background(), req.View, req.Target, user)
	}
	if req.Params == nil {
		return nil, deny("Parameters must be an object")
	}
	if mode == systemops.ModeRecover {
		return d.Recover(context.Background(), req)
	}
	active, err := d.Changing()
	if err != nil {
		return nil, err
	}
	if active {
		return nil, deny("A system update is in progress; wait for the panel to reconnect")
	}
	if mode == systemops.ModeExecute {
		r.Cancellable(true)
		defer r.Cancellable(false)
		if err := r.Checkpoint(); err != nil {
			return nil, err
		}
	}
	planned, err := d.Plan(context.Background(), req.Action, req.Params, user)
	if err != nil {
		return nil, err
	}
	if mode == systemops.ModePlan {
		return planned, nil
	}
	if mode != systemops.ModeExecute {
		return nil, deny("Unknown operation mode")
	}
	var p struct {
		Fingerprint  string `json:"fingerprint"`
		Confirmation string `json:"confirmation"`
	}
	if err := systemops.Decode(planned, &p); err != nil {
		return nil, err
	}
	if req.Fingerprint != p.Fingerprint || p.Fingerprint == "" {
		return nil, deny("State has changed. Review a new operation plan.")
	}
	if req.Confirmation != p.Confirmation {
		return nil, deny("The exact operation target was not confirmed")
	}
	// Recheck after potentially slow planning, before the non-cancellable boundary.
	fresh, err := d.Authorize(user)
	if err != nil {
		return nil, err
	}
	if fresh != id {
		return nil, deny("Account identity or access has changed; request a new operation plan")
	}
	active, err = d.Changing()
	if err != nil {
		return nil, err
	}
	if active {
		return nil, deny("A system update is in progress; wait for the panel to reconnect")
	}
	r.Cancellable(false)
	if err := r.Checkpoint(); err != nil {
		return nil, err
	}
	mutated = true
	return d.Execute(context.Background(), req.Action, req.Params, r)
}

func changing() (bool, error) {
	raw, err := os.ReadFile("/var/lib/panasms-updates/state.json")
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var state struct {
		Phase     string `json:"phase"`
		Operation string `json:"operation"`
	}
	if err := systemops.Decode(raw, &state); err != nil {
		return false, err
	}
	switch state.Phase {
	case "preparing", "backing-up", "installing", "verifying", "rolling-back", "recovery-required":
		return true, nil
	case "queued":
		return state.Operation == "install" || state.Operation == "rollback", nil
	}
	return false, nil
}
func query(ctx context.Context, view, target, user string) (json.RawMessage, error) {
	switch view {
	case "accounts":
		return accounts.Query(ctx, "")
	case "account-details":
		return accounts.Query(ctx, target)
	case "account-sessions":
		return accounts.Sessions(ctx, target)
	case "web-access":
		return webaccess.Default().Query()
	}
	return host.Query(ctx, view, target)
}
func plan(ctx context.Context, action string, p map[string]any, user string) (json.RawMessage, error) {
	if accounts.IsNative(action) {
		return accounts.Plan(ctx, action, p, user)
	}
	if action == "system.web-port" {
		return webaccess.Default().Plan(action, p)
	}
	return host.Plan(ctx, action, p)
}
func execute(ctx context.Context, action string, p map[string]any, r *systemops.Reporter) (json.RawMessage, error) {
	if accounts.IsNative(action) {
		return accounts.Execute(ctx, action, p, r)
	}
	if action == "system.web-port" {
		return webaccess.Default().Execute(p)
	}
	return host.Execute(ctx, action, p, r)
}
