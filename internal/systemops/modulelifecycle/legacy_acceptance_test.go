package modulelifecycle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

func acceptanceLegacy(t *testing.T, s lifecycle) {
	t.Helper()
	if err := acceptanceExecute(t, s, "module.disable", map[string]any{"target": "go14-app"}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	before, err := s.registry()
	if err != nil {
		t.Fatal(err)
	}
	identities := map[string]directoryIdentity{}
	func() {
		lease, err := acquireMaintenance(s.maintenance, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.file.Close()
		lock, err := s.lock(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if err := lease.critical(); err != nil {
			t.Fatal(err)
		}
		root, err := trustedDirectory(s.root, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if err := unix.Mkdirat(int(root.Fd()), ".transaction", 0700); err != nil {
			t.Fatal(err)
		}
		if err := root.Sync(); err != nil {
			t.Fatal(err)
		}
		state := &transaction{Before: before, Affected: []string{"go14-base", "go14-app"}}
		if err := s.saveTransaction(state); err != nil {
			t.Fatal(err)
		}
		gate, err := gatedRegistry(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.saveRegistry(gate); err != nil {
			t.Fatal(err)
		}
		if err := s.stopAffected(context.Background(), state, nil); err != nil {
			t.Fatal(err)
		}
		stage, err := s.transactionDirectory()
		if err != nil {
			t.Fatal(err)
		}
		defer stage.Close()
		for _, id := range state.Affected {
			identities[id], err = directoryAt(root, id, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Renameat2(int(root.Fd()), id, int(stage.Fd()), "old-"+id, unix.RENAME_NOREPLACE); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkdirat(int(root.Fd()), id, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(s.root, id, "uncommitted-code"), []byte("discard only owned code"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		if err := stage.Sync(); err != nil {
			t.Fatal(err)
		}
		if err := root.Sync(); err != nil {
			t.Fatal(err)
		}
	}()
	if err := s.recoverStartup(context.Background()); err != nil {
		t.Fatal("native startup failed to recover the three-field legacy journal", err)
	}
	current, err := s.registry()
	if err != nil || !registryEqual(before, current) || current["go14-app"]["enabled"] != false {
		t.Fatal("legacy recovery changed disabled intent", err)
	}
	root, err := trustedDirectory(s.root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, id := range []string{"go14-base", "go14-app"} {
		actual, err := directoryAt(root, id, 0)
		if err != nil || actual != identities[id] {
			t.Fatal("legacy backup incarnation was not restored", id, err)
		}
	}
	active, err := s.run(context.Background(), []string{"systemctl", "is-active", unit("go14-app")}, systemops.CommandOptions{Accepted: []int{0, 3, 4}})
	if err != nil || strings.TrimSpace(string(active)) != "inactive" {
		t.Fatal("legacy recovery started disabled module", err)
	}
	if err := acceptanceExecute(t, s, "module.enable", map[string]any{"target": "go14-app"}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS raw legacy journal recovers real payloads/services and preserves disabled intent")
}
