package worker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/systemops"
)

func TestStorageQueryMemberAuthorizationAndRedaction(t *testing.T) {
	for _, admin := range []bool{false, true} {
		d, _ := setup()
		d.Authorize = func(string) (auth.Identity, error) {
			role := "user"
			if admin {
				role = "admin"
			}
			return auth.Identity{Role: role}, nil
		}
		calls := 0
		d.Query = func(_ context.Context, view, target, user string) (json.RawMessage, error) {
			calls++
			if target != "requested" || user != "alice" {
				t.Fatal("query parameters changed")
			}
			return json.RawMessage(`{"devices":[{"serial":"private-value","nested":{"wwn":"private-wwn","size":100}}]}`), nil
		}
		result, err := d.Handle(systemops.ModeQuery, "alice", &systemops.Request{View: "storage-options", Target: "requested"}, reporter())
		if err != nil || calls != 1 {
			t.Fatalf("%v %d", err, calls)
		}
		if strings.Contains(string(result), "private-") != admin {
			t.Fatalf("admin=%v result=%s", admin, result)
		}
		for _, view := range []string{"raid-candidates", "storage-luks"} {
			calls = 0
			_, err = d.Handle(systemops.ModeQuery, "alice", &systemops.Request{View: view, Target: "requested"}, reporter())
			if admin && (err != nil || calls != 1) || !admin && (err == nil || calls != 0) {
				t.Fatalf("view=%s admin=%v err=%v calls=%d", view, admin, err, calls)
			}
		}
	}
}

func TestStorageQueryInvalidResultFailsBeforeExposure(t *testing.T) {
	d, _ := setup()
	d.Authorize = func(string) (auth.Identity, error) { return auth.Identity{Role: "user"}, nil }
	d.Query = func(context.Context, string, string, string) (json.RawMessage, error) {
		return json.RawMessage(`{"serial":"private-value"`), nil
	}
	result, err := d.Handle(systemops.ModeQuery, "alice", &systemops.Request{View: "storage-options"}, reporter())
	if err == nil || len(result) != 0 || !systemops.Unchanged(err) {
		t.Fatalf("%s %v", result, err)
	}
}

func TestMemberStorageQueryHidesSleepStateSerialKeys(t *testing.T) {
	for _, admin := range []bool{false, true} {
		d, _ := setup()
		d.Authorize = func(string) (auth.Identity, error) {
			role := "user"
			if admin {
				role = "admin"
			}
			return auth.Identity{Role: role}, nil
		}
		original := json.RawMessage(`{"sleepStatus":{"private-disk-serial:42":{"device":"/dev/sda","minutes":0,"status":"error","error":"sleep command failed"}}}`)
		d.Query = func(context.Context, string, string, string) (json.RawMessage, error) { return original, nil }
		result, err := d.Handle(systemops.ModeQuery, "alice", &systemops.Request{View: "storage-options"}, reporter())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(result), "private-disk-serial") != admin {
			t.Fatalf("admin=%v output=%s", admin, result)
		}
		var output map[string]any
		if err := json.Unmarshal(result, &output); err != nil {
			t.Fatal(err)
		}
		states, ok := output["sleepStatus"].(map[string]any)
		if !ok || len(states) != 1 {
			t.Fatalf("%v", output)
		}
		if !strings.Contains(string(result), "sleep command failed") || !strings.Contains(string(result), "/dev/sda") {
			t.Fatal("member observation lost", string(result))
		}
		if !strings.Contains(string(original), "private-disk-serial") {
			t.Fatal("admin input mutated")
		}
	}
}
