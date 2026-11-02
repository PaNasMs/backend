package profile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSMBSyncUsesNativeHelperAndStdinOnly(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "helper")
	args := filepath.Join(root, "args")
	body := filepath.Join(root, "body")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + args + "'\ncat > '" + body + "'\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := syncSMB(context.Background(), "alice", "fixture-only-password", helper); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(args)
	if err != nil || string(raw) != "sharing\nsync\n" {
		t.Fatal(string(raw), err)
	}
	raw, err = os.ReadFile(body)
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]string
	if err = json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	if request["user"] != "alice" || request["password"] != "fixture-only-password" {
		t.Fatal("stdin payload changed")
	}
}
func TestSMBSyncFailureRedactedAndCancelledLoginDoesNotWait(t *testing.T) {
	root := t.TempDir()
	helper := filepath.Join(root, "helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho fixture-only-password >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := syncSMB(context.Background(), "alice", "fixture-only-password", helper); err == nil || strings.Contains(err.Error(), "fixture-only-password") {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := syncSMB(ctx, "alice", "fixture-only-password", helper); err == nil {
		t.Fatal("cancelled helper succeeded")
	}
}
