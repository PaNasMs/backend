package worker

import (
	"context"
	"encoding/json"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/systemops"
	"testing"
)

func TestPartitionFilesystemActionsRemainAdministratorOnly(t *testing.T) {
	for _, action := range []string{"partition.create", "partition.delete", "partition.resize", "filesystem.format", "filesystem.remove", "filesystem.resize"} {
		for _, mode := range []systemops.Mode{systemops.ModePlan, systemops.ModeExecute, systemops.ModeRecover} {
			d, _ := setup()
			d.Authorize = func(string) (auth.Identity, error) { return auth.Identity{Role: "user"}, nil }
			d.Plan = func(context.Context, string, map[string]any, string) (json.RawMessage, error) {
				t.Fatal("member reached planner")
				return nil, nil
			}
			d.Execute = func(context.Context, string, map[string]any, *systemops.Reporter) (json.RawMessage, error) {
				t.Fatal("member reached executor")
				return nil, nil
			}
			d.Recover = func(context.Context, *systemops.Request) (json.RawMessage, error) {
				t.Fatal("member reached recovery metadata")
				return nil, nil
			}
			_, err := d.Handle(mode, "member", &systemops.Request{Action: action, Params: map[string]any{"target": "/dev/example"}}, reporter())
			if err == nil || !systemops.Unchanged(err) {
				t.Fatalf("%s %s %v", mode, action, err)
			}
		}
	}
}
