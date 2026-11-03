package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/systemops"
	"strconv"
	"testing"
)

func setup() (Dispatcher, *int) {
	calls := new(int)
	return Dispatcher{
		Authorize: func(string) (auth.Identity, error) {
			return auth.Identity{UID: 1000, Username: "admin", Role: "admin", Epoch: "epoch", Principal: "principal"}, nil
		}, Changing: func() (bool, error) { return false, nil }, Plan: func(context.Context, string, map[string]any, string) (json.RawMessage, error) {
			return json.RawMessage(`{"fingerprint":"fresh","confirmation":"target"}`), nil
		}, Execute: func(context.Context, string, map[string]any, *systemops.Reporter) (json.RawMessage, error) {
			*calls++
			return json.RawMessage(`{}`), nil
		}, Query: func(context.Context, string, string, string) (json.RawMessage, error) {
			return json.RawMessage(`{}`), nil
		}, Recover: func(context.Context, *systemops.Request) (json.RawMessage, error) { return json.RawMessage(`{}`), nil }}, calls
}
func request() *systemops.Request {
	return &systemops.Request{Action: "group.create", Params: map[string]any{"target": "target"}, Fingerprint: "fresh", Confirmation: "target"}
}
func reporter() *systemops.Reporter {
	return systemops.NewReporter(io.Discard, func(string) string { return "" })
}

func TestModuleExecutionKeepsOriginalIdentityRecheckAfterSlowStages(t *testing.T) {
	d, _ := setup()
	checks := 0
	authorize := d.Authorize
	d.Authorize = func(user string) (auth.Identity, error) {
		id, err := authorize(user)
		checks++
		if checks >= 3 {
			id.Epoch = "revoked-after-internal-planning"
		}
		return id, err
	}
	d.Execute = func(ctx context.Context, _ string, _ map[string]any, _ *systemops.Reporter) (json.RawMessage, error) {
		callback, ok := ctx.Value(moduleAuthorizationKey{}).(func() error)
		if !ok {
			t.Fatal("original authorization callback missing")
		}
		return nil, callback()
	}
	req := request()
	req.Action = "module.install"
	if _, err := d.Handle(systemops.ModeExecute, "admin", req, reporter()); err == nil || checks != 3 {
		t.Fatal(checks, err)
	}
}

func TestMemberModuleQueryPreservesTargetAndFilterContext(t *testing.T) {
	d, _ := setup()
	d.Authorize = func(string) (auth.Identity, error) { return auth.Identity{Role: "user"}, nil }
	d.Query = func(ctx context.Context, view, target, user string) (json.RawMessage, error) {
		member, _ := ctx.Value(moduleMemberKey{}).(bool)
		if view != "modules" || target != "" || user != "alice" || !member {
			t.Fatal(view, target, user, member)
		}
		return json.RawMessage(`{"installed":[]}`), nil
	}
	if _, err := d.Handle(systemops.ModeQuery, "alice", &systemops.Request{View: "modules"}, reporter()); err != nil {
		t.Fatal(err)
	}
}
func TestRejectedBeforeMutation(t *testing.T) {
	for _, reason := range []string{"denied", "ordinary", "updater", "stale", "confirmation", "identity", "reauthorization"} {
		t.Run(reason, func(t *testing.T) {
			d, calls := setup()
			req := request()
			switch reason {
			case "denied":
				d.Authorize = func(string) (auth.Identity, error) { return auth.Identity{}, errors.New("denied") }
			case "ordinary":
				d.Authorize = func(string) (auth.Identity, error) { return auth.Identity{Role: "user"}, nil }
			case "updater":
				d.Changing = func() (bool, error) { return true, nil }
			case "stale":
				req.Fingerprint = "stale"
			case "confirmation":
				req.Confirmation = "other"
			case "identity":
				req.Actor = &systemops.Actor{UID: 999}
			case "reauthorization":
				count := 0
				original := d.Authorize
				d.Authorize = func(u string) (auth.Identity, error) {
					id, err := original(u)
					count++
					if count == 2 {
						id.Epoch = "revoked"
					}
					return id, err
				}
			}
			_, err := d.Handle(systemops.ModeExecute, "admin", req, reporter())
			if err == nil || !systemops.Unchanged(err) || *calls != 0 {
				t.Fatal(err, *calls)
			}
		})
	}
}
func TestMutationFailureIsNotNoChanges(t *testing.T) {
	d, calls := setup()
	d.Execute = func(context.Context, string, map[string]any, *systemops.Reporter) (json.RawMessage, error) {
		*calls++
		return nil, errors.New("partial")
	}
	_, err := d.Handle(systemops.ModeExecute, "admin", request(), reporter())
	if err == nil || systemops.Unchanged(err) || *calls != 1 {
		t.Fatal(err, *calls)
	}
}
func TestCancelBeforeMutation(t *testing.T) {
	for _, duringPlan := range []bool{false, true} {
		d, calls := setup()
		read, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		r := systemops.NewReporter(io.Discard, func(string) string { return strconv.Itoa(int(read.Fd())) })
		defer r.Close()
		defer write.Close()
		if duringPlan {
			plan := d.Plan
			d.Plan = func(ctx context.Context, a string, p map[string]any, u string) (json.RawMessage, error) {
				write.Close()
				return plan(ctx, a, p, u)
			}
		} else {
			write.Close()
		}
		_, err = d.Handle(systemops.ModeExecute, "admin", request(), r)
		if !errors.Is(err, systemops.ErrCancelled) || *calls != 0 {
			t.Fatal(err, *calls)
		}
	}
}
func TestOrdinaryQueriesAreOwnerScoped(t *testing.T) {
	d, _ := setup()
	d.Authorize = func(string) (auth.Identity, error) { return auth.Identity{Role: "user"}, nil }
	d.Query = func(_ context.Context, view, target, user string) (json.RawMessage, error) {
		if target != "alice" {
			t.Fatal("owner scope lost", target)
		}
		return json.RawMessage(`{}`), nil
	}
	for _, view := range []string{"account-details", "account-sessions"} {
		if _, err := d.Handle(systemops.ModeQuery, "alice", &systemops.Request{View: view, Target: "admin"}, reporter()); err != nil {
			t.Fatal(err)
		}
	}
	for _, view := range []string{"accounts", "homes", "homes-check", "sharing", "share-folders", "nfs"} {
		if _, err := d.Handle(systemops.ModeQuery, "alice", &systemops.Request{View: view}, reporter()); err == nil {
			t.Fatal("ordinary query allowed", view)
		}
	}
}

func TestHomesMutationRetainsValidatedPlanUnderDomainLock(t *testing.T) {
	d, calls := setup()
	req := request()
	req.Action = "homes.move"
	d.Execute = func(ctx context.Context, action string, p map[string]any, r *systemops.Reporter) (json.RawMessage, error) {
		*calls++
		if got, _ := ctx.Value(validatedPlanKey{}).(string); got != "fresh" {
			t.Fatal("validated fingerprint lost", got)
		}
		return json.RawMessage(`{}`), nil
	}
	if _, err := d.Handle(systemops.ModeExecute, "admin", req, reporter()); err != nil || *calls != 1 {
		t.Fatal(err, *calls)
	}
}
func TestRecoveryNeverExecutes(t *testing.T) {
	d, calls := setup()
	d.Plan = func(context.Context, string, map[string]any, string) (json.RawMessage, error) {
		t.Fatal("recovery planned mutation")
		return nil, nil
	}
	if _, err := d.Handle(systemops.ModeRecover, "admin", request(), reporter()); err != nil || *calls != 0 {
		t.Fatal(err, *calls)
	}
}

func TestSharingMutationsRemainAdministratorOnly(t *testing.T) {
	d, calls := setup()
	d.Authorize = func(string) (auth.Identity, error) { return auth.Identity{Role: "user"}, nil }
	for _, action := range []string{"share.save", "share.remove", "share.account", "share.disconnect", "share.recover", "nfs.export", "nfs.export-remove"} {
		req := request()
		req.Action = action
		if _, err := d.Handle(systemops.ModeExecute, "alice", req, reporter()); err == nil {
			t.Fatal("ordinary mutation allowed", action)
		}
	}
	if *calls != 0 {
		t.Fatal("unauthorized sharing mutation executed")
	}
}

func TestSharingAccountRecoveryReportsUnknownEffectiveAccess(t *testing.T) {
	raw, err := recoverOperation(context.Background(), &systemops.Request{Action: "share.account", Params: map[string]any{"target": "alice"}})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Checks []struct {
			Label string
			Value string
		}
		RecoveryAction any
		Route          string
		Message        string
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Checks) != 2 || result.Checks[0].Label != "Account" || result.Checks[0].Value != "alice" || result.Checks[1].Label != "SMB access" || result.Checks[1].Value != "Unknown" || result.RecoveryAction != nil || result.Route != "/sharing" {
		t.Fatal(string(raw))
	}
	for _, target := range []any{nil, "bad/name"} {
		if _, err := recoverOperation(context.Background(), &systemops.Request{Action: "share.account", Params: map[string]any{"target": target}}); err == nil {
			t.Fatal("invalid target accepted", target)
		}
	}
}

func TestPersonalFolderQueryKeepsAuthenticatedUserAndRequestedPath(t *testing.T) {
	d, _ := setup()
	d.Authorize = func(string) (auth.Identity, error) {
		return auth.Identity{Role: "user", UID: 1000, Username: "member"}, nil
	}
	calls := 0
	d.Query = func(_ context.Context, view, target, user string) (json.RawMessage, error) {
		calls++
		if view != "personal-folders" || target != "/home/member/subdir" || user != "member" {
			t.Fatal(view, target, user)
		}
		return json.RawMessage(`{}`), nil
	}
	if _, err := d.Handle(systemops.ModeQuery, "member", &systemops.Request{View: "personal-folders", Target: "/home/member/subdir"}, reporter()); err != nil {
		t.Fatal(err)
	}
	for _, view := range []string{"home-folders", "data-folders", "mount-folders"} {
		if _, err := d.Handle(systemops.ModeQuery, "member", &systemops.Request{View: view}, reporter()); err == nil {
			t.Fatal(view)
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}

func TestNetworkRecoveryInspectionRequiresAdministrator(t *testing.T) {
	d, _ := setup()
	called := false
	d.Authorize = func(string) (auth.Identity, error) { return auth.Identity{UID: 1000, Role: "user"}, nil }
	d.Recover = func(context.Context, *systemops.Request) (json.RawMessage, error) {
		called = true
		return json.RawMessage(`{}`), nil
	}
	_, err := d.Handle(systemops.ModeRecover, "member", &systemops.Request{Action: "smb.mount", Params: map[string]any{"point": "/mnt/share"}}, reporter())
	if err == nil || called {
		t.Fatal("member reached admin recovery inspection", err)
	}
}
