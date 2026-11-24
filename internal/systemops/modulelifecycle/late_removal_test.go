package modulelifecycle

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverPartiallyRemovedSigners(t *testing.T) {
	s, _, _ := catalogFixture(t)
	dir, err := s.configDir()
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	// The source list was committed and the first key removed before a crash.
	c := sourceChange{Sources: []Manifest{}, RemovePublishers: []string{"retired-a", "retired-b"}}
	for name, value := range map[string]any{sourceFile: c.Sources, sourceIntent: c} {
		if err := atomicAt(dir, name, mustJSON(t, value), 0600, s.owner); err != nil {
			t.Fatal(err)
		}
	}
	remaining := filepath.Join(s.keys, "retired-b.pem")
	if err := os.WriteFile(remaining, []byte("fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.recoverStartup(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{remaining, filepath.Join(dir.Name(), sourceIntent)} {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("expected %s absent: %v", path, err)
			}
		}
	}
}

func TestLateMultiSignerRemoval(t *testing.T) {
	for _, multi := range []bool{false, true} {
		name := "single"
		ids := []any{"retired-a"}
		if multi {
			name = "multi"
			ids = append(ids, "retired-b", "shared", "panasms-ci")
		}
		t.Run(name, func(t *testing.T) {
			s, _, _ := catalogFixture(t)
			dir, e := s.configDir()
			if e != nil {
				t.Fatal(e)
			}
			defer dir.Close()
			rows := []Manifest{{"id": "retired", "url": "https://example.org/", "signers": ids}, {"id": "kept", "url": "https://example.net/", "signers": []any{"shared"}}}
			if e = atomicAt(dir, sourceFile, mustJSON(t, rows), 0600, s.owner); e != nil {
				t.Fatal(e)
			}
			for _, id := range []string{"retired-a", "retired-b", "shared", "panasms-ci"} {
				if e = os.WriteFile(filepath.Join(s.keys, id+".pem"), []byte("fixture"), 0644); e != nil {
					t.Fatal(e)
				}
			}
			p := map[string]any{"target": "retired"}
			fp := executionPlan(t, s, "module.source-remove", p)
			if _, e = s.execute(context.Background(), "module.source-remove", p, "alice", fp, nil, func() error { return nil }); e != nil {
				t.Fatal(e)
			}
			rows, e = s.sources()
			if e != nil || len(rows) != 1 || rows[0]["id"] != "kept" {
				t.Fatal(rows, e)
			}
			for _, id := range []string{"shared", "panasms-ci"} {
				if _, e = os.Stat(filepath.Join(s.keys, id+".pem")); e != nil {
					t.Fatal(e)
				}
			}
			removed := []string{"retired-a"}
			if multi {
				removed = append(removed, "retired-b")
			}
			for _, id := range removed {
				if _, e = os.Stat(filepath.Join(s.keys, id+".pem")); !os.IsNotExist(e) {
					t.Errorf("revoked key retained: %s", id)
				}
			}
		})
	}
}
