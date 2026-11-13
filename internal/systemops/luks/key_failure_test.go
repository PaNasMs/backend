package luks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"panasms.local/backend/internal/systemops"
)

func TestKeyCredentialFailuresLeaveStateUnchanged(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cryptsetup"), []byte("#!/bin/sh\ncat >&2\nexit 2\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	p := &prepared{Meta: luksMetadata{UsableSlots: []int{0, 1, 31}}, Extra: extraState{Config: &managedConfig{Slot: 31}}}
	const secret = "fixture credential"
	for _, action := range []string{"luks.key-add", "luks.auto-enable", "luks.key-remove", "luks.auto-disable"} {
		_, err := executeExtra(context.Background(), action, map[string]any{"passphrase": secret, "slot": 1}, p, "/dev/fixture", nil)
		if !systemops.Unchanged(err) || !strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), secret) {
			t.Errorf("%s: %v", action, err)
		}
	}
}

func TestVerificationAfterKeyAdditionDoesNotClaimUnchanged(t *testing.T) {
	dir := t.TempDir()
	const script = "#!/bin/sh\ninput=$(cat)\ncase $1 in\nluksAddKey) touch \"$(dirname \"$0\")/mutated\";;\nopen) test \"$input\" = original || exit 2;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "cryptsetup"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	_, err := executeExtra(context.Background(), "luks.key-add", map[string]any{"passphrase": "original", "password": "replacement"}, &prepared{Extra: extraState{}}, "/dev/fixture", nil)
	if err == nil || systemops.Unchanged(err) {
		t.Fatalf("expected a post-mutation failure: %v", err)
	}
	if _, err = os.Stat(filepath.Join(dir, "mutated")); err != nil {
		t.Fatal("key addition was not reached", err)
	}
}
