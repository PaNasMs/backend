package systemops

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, "backups")
	target := filepath.Join(dir, "conf")

	if err := atomicWrite(target, "first", 0o600, backup); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "first" {
		t.Fatalf("read after first write: %q %v", data, err)
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}

	// Second write must back up the previous contents.
	if err := atomicWrite(target, "second", 0o600, backup); err != nil {
		t.Fatalf("replace: %v", err)
	}
	data, _ = os.ReadFile(target)
	if string(data) != "second" {
		t.Errorf("content after replace = %q, want second", data)
	}
	entries, err := os.ReadDir(backup)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one backup, got %d (%v)", len(entries), err)
	}
	saved, _ := os.ReadFile(filepath.Join(backup, entries[0].Name()))
	if string(saved) != "first" {
		t.Errorf("backup content = %q, want first", saved)
	}
}

func TestAtomicWriteRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	err := atomicWrite(link, "attempt", 0o600, filepath.Join(dir, "backups"))
	if !IsRejected(err) {
		t.Fatalf("expected rejection writing through symlink, got %v", err)
	}
	// The symlink target must be untouched.
	data, _ := os.ReadFile(real)
	if string(data) != "x" {
		t.Errorf("symlink target modified: %q", data)
	}
}

func TestAtomicWriteNoTempLeak(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "conf")
	if err := atomicWrite(target, "data", 0o600, filepath.Join(dir, "backups")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if len(e.Name()) >= 9 && e.Name()[:9] == ".panasms-" {
			t.Errorf("temp file leaked: %s", e.Name())
		}
	}
}
