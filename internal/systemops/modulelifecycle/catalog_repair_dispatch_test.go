package modulelifecycle_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/modulelifecycle"
	"panasms.local/backend/internal/systemops/worker"
)

func TestDispatcherReportsChangesAfterCatalogRepair(t *testing.T) {
	for _, phase := range []string{"replan", "after-replan", "authorization", "execute", "legacy", "query", "recover"} {
		t.Run(phase, func(t *testing.T) {
			catalog := modulelifecycle.InterruptedCatalogForDispatcher(t, phase == "legacy")
			d := worker.New()
			d.Authorize = func(string) (auth.Identity, error) { return auth.Identity{Role: "admin"}, nil }
			d.Changing = func() (bool, error) { return false, nil }
			d.Query = func(ctx context.Context, view, _, _ string) (json.RawMessage, error) {
				return catalog.Query(ctx, view)
			}
			d.Recover = func(ctx context.Context, req *systemops.Request) (json.RawMessage, error) {
				return catalog.Recover(ctx, req.Action)
			}
			d.Plan = func(ctx context.Context, action string, p map[string]any, _ string) (json.RawMessage, error) {
				if phase == "authorization" {
					if _, err := catalog.Plan(ctx, action, p); err != nil {
						return nil, err
					}
				}
				if phase == "execute" || phase == "authorization" {
					return json.RawMessage(`{"fingerprint":"stale","confirmation":"fixture"}`), nil
				}
				return catalog.Plan(ctx, action, p)
			}
			d.Execute = func(ctx context.Context, action string, p map[string]any, r *systemops.Reporter) (json.RawMessage, error) {
				return catalog.Execute(ctx, action, p, "stale", r, func() error {
					if phase == "authorization" {
						return errors.New("authorization expired")
					}
					return nil
				})
			}
			target := "fixture"
			if phase == "replan" {
				target = "missing"
			}
			req := systemops.Request{Action: "module.source-remove", Params: map[string]any{"target": target}, Fingerprint: "stale", Confirmation: "fixture"}
			mode := systemops.ModeExecute
			if phase == "query" || phase == "recover" {
				if err := os.WriteFile(catalog.Config, []byte("invalid config"), 0600); err != nil {
					t.Fatal(err)
				}
				mode = systemops.ModeRecover
				if phase == "query" {
					mode = systemops.ModeQuery
					req.Action = ""
					req.View = "module-catalog"
				}
			}
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			for _, wantNoChanges := range []bool{false, true} {
				var out bytes.Buffer
				r := systemops.NewReporter(io.Discard, func(string) string { return "" })
				if err := systemops.Run(mode, "admin", bytes.NewReader(raw), &out, r, d.Handle); err != nil {
					t.Fatal(err)
				}
				var result systemops.Result
				if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.Error == "" || result.NoChanges != wantNoChanges {
					t.Fatalf("unexpected worker response: %s (%v)", out.Bytes(), err)
				}
			}
			if phase == "legacy" {
				if _, err := os.Stat(catalog.Key); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("legacy repair did not retire key: %v", err)
				}
			}
			if _, err := os.Stat(catalog.Journal); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("source-add journal was not repaired: %v", err)
			}
		})
	}
}
