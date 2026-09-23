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
	if _, err := d.Handle(systemops.ModeQuery, "alice", &systemops.Request{View: "accounts"}, reporter()); err == nil {
		t.Fatal("ordinary list allowed")
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
