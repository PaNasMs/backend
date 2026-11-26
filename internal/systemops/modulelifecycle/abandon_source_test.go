package modulelifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAbandonSourceAddHonorsLocks(t *testing.T) {
	for _, which := range []string{"maintenance", "lifecycle"} {
		t.Run(which, func(t *testing.T) {
			s, dir, _ := addPending(t)
			if err := os.Remove(filepath.Join(s.keys, "catalog.pem")); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir.Name(), sourceIntent)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var lock *os.File
			if which == "maintenance" {
				lock, err = os.Open(s.maintenance)
				if err == nil {
					err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
				}
			} else {
				lock, err = s.lock(context.Background(), nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if err := s.abandonSourceAdd(ctx, fmt.Sprintf("%x", sha256.Sum256(raw))); err == nil {
				t.Fatal("proceeded despite lock")
			}
			if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, raw) {
				t.Fatal("pending evidence changed", err)
			}
		})
	}
}

func TestAbandonSourceAdd(t *testing.T) {
	s, dir, _ := addPending(t)
	ctx := context.Background()
	key := filepath.Join(s.keys, "catalog.pem")
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	addIndependent(t, s, dir, "indep")
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir.Name(), name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	raw, rows := read(sourceIntent), read(sourceFile)
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	assertSourceConflict(t, s, dir)
	// Simulate losing the final directory sync, after the atomic rename.
	original := syncDir
	t.Cleanup(func() { syncDir = original })
	lost := errors.New("directory sync interrupted")
	syncDir = func(*os.File) error { return lost }
	if err := s.abandonSourceAdd(ctx, digest); !errors.Is(err, lost) {
		t.Fatalf("expected sync failure, got %v", err)
	}
	syncDir = original
	for i := 0; i < 2; i++ {
		if err := s.abandonSourceAdd(ctx, digest); err != nil {
			t.Fatal(err)
		}
		if err := s.recoverStartup(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(read("module-sources.abandoned-"+digest+".json"), raw) || !bytes.Equal(read(sourceFile), rows) {
		t.Fatal("archive or independent source bytes changed")
	}
	assertAbsent(t, key)
	assertAbsent(t, filepath.Join(dir.Name(), sourceIntent))
	if b, err := os.ReadFile(filepath.Join(s.keys, "indep.pem")); err != nil || string(b) != "independent" {
		t.Fatal("independent key changed", err)
	}
	// A subsequent pending decision must not be mistaken for a completed retry.
	next := append(bytes.Clone(raw), '\n')
	if err := atomicAt(dir, sourceIntent, next, 0600, s.owner); err != nil {
		t.Fatal(err)
	}
	if err := s.abandonSourceAdd(ctx, digest); err == nil || !bytes.Equal(read(sourceIntent), next) {
		t.Fatal("stale digest accepted or new intent changed")
	}
}

func TestAbandonSourceAddRefusals(t *testing.T) {
	for _, condition := range []string{"visible", "key-present", "mixed-withdrawal", "legacy", "stage", "archive-exists", "invalid-digest"} {
		t.Run(condition, func(t *testing.T) {
			s, dir, c := addPending(t)
			key := filepath.Join(s.keys, "catalog.pem")
			if condition != "key-present" {
				if err := os.Remove(key); err != nil {
					t.Fatal(err)
				}
			}
			put := func(name string, data []byte) {
				t.Helper()
				if err := atomicAt(dir, name, data, 0600, s.owner); err != nil {
					t.Fatal(err)
				}
			}
			switch condition {
			case "visible":
				put(sourceFile, mustJSON(t, c.Sources))
			case "mixed-withdrawal":
				c.Remove = true
			case "legacy":
				c.Add = nil
			case "stage":
				put(sourceStagePrefix+"evidence", []byte("stage"))
			}
			raw := mustJSON(t, c)
			put(sourceIntent, raw)
			digest := fmt.Sprintf("%x", sha256.Sum256(raw))
			if condition == "archive-exists" {
				put("module-sources.abandoned-"+digest+".json", []byte("earlier evidence"))
			}
			if condition == "invalid-digest" {
				digest = ""
			}
			if err := s.abandonSourceAdd(context.Background(), digest); err == nil {
				t.Fatal("unexpected success")
			}
			if got, err := os.ReadFile(filepath.Join(dir.Name(), sourceIntent)); err != nil || !bytes.Equal(got, raw) {
				t.Fatal("pending evidence changed", err)
			}
			if condition == "key-present" {
				if got, err := os.ReadFile(key); err != nil || !bytes.Equal(got, c.Key) {
					t.Fatal("key changed", err)
				}
			} else {
				assertAbsent(t, key)
			}
		})
	}
}
