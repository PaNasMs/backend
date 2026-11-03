package localmounts

import (
	"context"
	"errors"
	"os"
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
	"testing"
)

func testJournal() *transaction {
	return &transaction{TransactionEnvelope: storagebase.TransactionEnvelope{Schema: 1, Domain: "localmounts", Action: "disk.prepare", Target: "/dev/sda", Phase: "pending", Identity: storagequery.StorageIdentity{BootID: "boot", Devices: []storagequery.DeviceIdentity{{Path: "/dev/sda", DeviceNumber: "8:0", DiskSequence: "9"}}}}}
}
func TestJournalPersistsIntentBeforeCommand(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	state := testJournal()
	save := func(v *transaction) error { return writeJournal(root, os.Getuid(), v) }
	failed := errors.New("write interrupted")
	err := step(state, "wipe", save, func() error {
		disk, _, err := readJournal(root, "/dev/sda", os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		if len(disk.Steps) != 1 || disk.Steps[0].Completed {
			t.Fatalf("intent missing: %+v", disk)
		}
		return failed
	})
	if !errors.Is(err, failed) {
		t.Fatal(err)
	}
	disk, _, err := readJournal(root, "/dev/sda", os.Getuid())
	if err != nil || disk.Steps[0].Completed {
		t.Fatalf("uncertain command marked complete: %+v %v", disk, err)
	}
	called := false
	err = step(state, "second", func(*transaction) error { return failed }, func() error { called = true; return nil })
	if called || !errors.Is(err, failed) {
		t.Fatal("command ran before durable intent")
	}
}
func TestJournalHistoryLeavesActiveUntilReplacement(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	state := testJournal()
	if err := writeJournal(root, os.Getuid(), state); err != nil {
		t.Fatal(err)
	}
	_, revision, err := readJournal(root, state.Target, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	if err = archiveJournal(root, state.Target, revision, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	_, again, err := readJournal(root, state.Target, os.Getuid())
	if err != nil || again != revision {
		t.Fatal("active evidence lost before replacement", err)
	}
	if err = archiveJournal(root, state.Target, revision, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	state.Phase = "complete"
	if err = writeJournal(root, os.Getuid(), state); err != nil {
		t.Fatal(err)
	}
	history, err := os.ReadFile(journalPath(root, state.Target) + ".history-" + revision)
	if err != nil || storagebase.Hash(string(history)) != revision {
		t.Fatal("history changed", err)
	}
	if err = archiveJournal(root, state.Target, revision, os.Getuid()); err == nil {
		t.Fatal("stale plan accepted")
	}
}

func TestDetachClearsInterruptedMountAfterItDisappears(t *testing.T) {
	s := fixtureService(t)
	state := testJournal()
	state.Action = "mount.attach"
	state.MountID = 101
	if err := writeJournal(s.root, s.owner, state); err != nil {
		t.Fatal(err)
	}
	params := map[string]any{"target": state.Target}
	if _, err := s.prepare(context.Background(), "mount.detach", params, "admin"); err != nil {
		t.Fatal(err)
	}
	s.mounts = func() ([]folders.LiveMount, error) {
		return []folders.LiveMount{{ID: 101, Device: "8:97", Target: "/mnt/changed", Root: "/"}}, nil
	}
	if plan, err := s.prepare(context.Background(), "mount.detach", params, "admin"); err != nil || len(plan.selected) != 0 {
		t.Fatalf("unrelated reused mount ID blocked cleanup: %v", err)
	}
	state.Identity.Devices[0].DeviceNumber = "8:97"
	if err := writeJournal(s.root, s.owner, state); err != nil {
		t.Fatal(err)
	}
	if _, err := s.prepare(context.Background(), "mount.detach", params, "admin"); err == nil {
		t.Fatal("the recorded volume is still mounted")
	}
	state.Identity.BootID = "older-boot"
	if err := writeJournal(s.root, s.owner, state); err != nil {
		t.Fatal(err)
	}
	plan, err := s.prepare(context.Background(), "mount.detach", params, "admin")
	if err != nil || len(plan.selected) != 0 {
		t.Fatalf("reused id treated as old mount: %v", err)
	}
}

func TestDetachCannotDiscardBtrfsEvidenceFromSourceSpelling(t *testing.T) {
	s := fixtureService(t)
	state := testJournal()
	state.Action = "mount.attach"
	state.FSType = "btrfs"
	state.Identity.Devices[0].UUID = "retained"
	state.MountID = 101
	if err := writeJournal(s.root, s.owner, state); err != nil {
		t.Fatal(err)
	}
	s.mounts = func() ([]folders.LiveMount, error) {
		return []folders.LiveMount{{ID: 101, Device: "0:97", Target: "/mnt/go09b-missing-proof", Root: "/", FSType: "btrfs", Source: "/dev/disk/by-label/data"}}, nil
	}
	for _, tc := range []struct {
		uuid    string
		blocked bool
	}{{"retained", true}, {"other-filesystem", false}} {
		inspected := false
		s.btrfsUUID = func(live folders.LiveMount) (string, error) {
			if live.ID != 101 {
				t.Fatal("wrong mount inspected")
			}
			inspected = true
			return tc.uuid, nil
		}
		_, err := s.prepare(context.Background(), "mount.detach", map[string]any{"target": state.Target}, "admin")
		if !inspected || (err != nil) != tc.blocked || (err != nil && err.Error() != "The mount changed; review a new operation plan") {
			t.Fatalf("UUID %s inspected=%v err=%v", tc.uuid, inspected, err)
		}
	}
}
