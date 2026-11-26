package modulelifecycle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An editor opened the old live inode before the add and saves through that
// descriptor during normal commit cleanup (no process restart).
func TestAddKeepsPreviousSourceOpenForEditing(t *testing.T) {
	s, _, _ := catalogFixture(t)
	dir := filepath.Dir(s.keys)
	path := filepath.Join(dir, sourceFile)
	if err := os.WriteFile(path, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	editor, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer editor.Close()
	p := map[string]any{"url": officialSource()["url"]}
	ctx := context.Background()
	plan, err := s.prepare(ctx, "module.source-add", p, "alice")
	if err != nil {
		t.Fatal(err)
	}
	saved := false
	original := syncDir
	defer func() { syncDir = original }()
	syncDir = func(d *os.File) error {
		if old, e := editor.Stat(); e == nil && !saved {
			if live, e := os.Stat(path); e == nil && !os.SameFile(old, live) {
				if _, e = editor.WriteAt([]byte("[ ]\n"), 0); e != nil {
					t.Fatal(e)
				}
				saved = true
			}
		}
		return original(d)
	}
	_, err = s.execute(ctx, "module.source-add", p, "alice", plan.fingerprint, nil, func() error { return nil })
	if !saved {
		t.Fatalf("did not exercise displaced descriptor: %v", err)
	}
	entries, e := os.ReadDir(dir)
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("expected a conflict, got %v", err)
	}
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		raw, e := os.ReadFile(filepath.Join(dir, entry.Name()))
		if e == nil && string(raw) == "[ ]\n" {
			return
		}
	}
	t.Fatalf("old descriptor's save lost during add cleanup: %v", err)
}

func TestManualSaveAtSourceExchange(t *testing.T) {
	for _, operation := range []string{"add", "remove"} {
		for _, mode := range []string{"normal", "recovery"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				s, _, _ := catalogFixture(t)
				ctx := context.Background()
				dir, err := s.configDir()
				if err != nil {
					t.Fatal(err)
				}
				defer dir.Close()
				rows := []Manifest{}
				action := "module.source-" + operation
				p := map[string]any{"url": officialSource()["url"]}
				if operation == "remove" {
					rows = append(rows, officialSource())
					p = map[string]any{"target": "panasms-official"}
				}
				path := filepath.Join(dir.Name(), sourceFile)
				if err = os.WriteFile(path, mustJSON(t, rows), 0600); err != nil {
					t.Fatal(err)
				}
				plan, err := s.prepare(ctx, action, p, "alice")
				if err != nil {
					t.Fatal(err)
				}
				edit := mustJSON(t, append(rows, Manifest{"id": "manual", "url": "https://example.com/manual/", "signers": []any{"editor"}}))
				original := exchangeSource
				t.Cleanup(func() { exchangeSource = original })
				exchangeSource = func(fd int, stage string) error {
					tmp := filepath.Join(dir.Name(), "editor-save")
					if e := os.WriteFile(tmp, edit, 0600); e != nil {
						t.Fatal(e)
					}
					if e := os.Rename(tmp, path); e != nil {
						t.Fatal(e)
					}
					return original(fd, stage)
				}
				if mode == "normal" {
					_, err = s.execute(ctx, action, p, "alice", plan.fingerprint, nil, func() error { return nil })
				} else {
					if err = atomicAt(dir, sourceIntent, mustJSON(t, plan.source), 0600, s.owner); err != nil {
						t.Fatal(err)
					}
					err = s.recoverStartup(ctx)
				}
				for i := 0; i < 2; i++ {
					if err == nil || !strings.Contains(err.Error(), "configuration conflict") {
						t.Fatalf("missing conflict: %v", err)
					}
					matches, e := filepath.Glob(filepath.Join(dir.Name(), sourceStagePrefix+"*"))
					if e != nil || len(matches) != 1 {
						t.Fatalf("missing preserved stage: %v %v", matches, e)
					}
					got, e := os.ReadFile(matches[0])
					if e != nil || string(got) != string(edit) {
						t.Fatalf("manual edit not preserved: %s %v", got, e)
					}
					if _, e = os.Stat(filepath.Join(dir.Name(), sourceIntent)); e != nil {
						t.Fatal(e)
					}
					if i == 0 {
						exchangeSource = original
						err = s.recoverStartup(ctx)
					}
				}
			})
		}
	}
}
