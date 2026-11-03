package localmounts

import (
	"errors"
	"os"
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
