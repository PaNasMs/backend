package modulelifecycle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"panasms.local/backend/internal/systemops"
)

func TestPreJournalCrashRecoveryOnlyRemovesOwnedEmptyOrTemporaryStaging(t *testing.T) {
	for _, name := range []string{"", ".write-" + strings.Repeat("a", 32), ".panasms-abcd123_"} {
		t.Run(name, func(t *testing.T) {
			s := transactionStore(t)
			if name != "" {
				if err := os.WriteFile(filepath.Join(s.root, ".transaction", name), []byte("partial before journal rename"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			state, err := s.loadTransaction()
			if err != nil || state == nil || !state.orphan || state.orphanFingerprint == "" {
				t.Fatal(state, err)
			}
			if err = s.saveTransaction(state); err == nil {
				t.Fatal("orphan minted a replacement journal")
			}
			r := recovery{store: s, mounts: func() ([]string, error) { return []string{}, nil }, run: func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
				t.Fatal("prejournal cleanup touched services")
				return nil, nil
			}}
			if err = r.restore(context.Background(), state, nil); err != nil {
				t.Fatal(err)
			}
			if _, err = os.Stat(filepath.Join(s.root, ".transaction")); !os.IsNotExist(err) {
				t.Fatal("owned orphan not removed", err)
			}
		})
	}
}

func TestPreJournalRecoveryRejectsUnknownLinkedWritableAndChangedFiles(t *testing.T) {
	for _, variant := range []string{"unknown", "directory", "symlink", "hardlink", "writable", "changed-after-plan", "mount"} {
		t.Run(variant, func(t *testing.T) {
			s := transactionStore(t)
			path := filepath.Join(s.root, ".transaction", ".write-"+strings.Repeat("a", 32))
			if err := os.WriteFile(path, []byte("partial"), 0600); err != nil {
				t.Fatal(err)
			}
			planned, err := s.loadTransaction()
			if err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "unknown":
				if err = os.WriteFile(filepath.Join(s.root, ".transaction/user-data"), []byte("preserved"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err = os.Mkdir(filepath.Join(s.root, ".transaction/unknown"), 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err = os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(path+".saved", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err = os.Link(path, filepath.Join(s.root, "linked")); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err = os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "changed-after-plan":
				if err = os.WriteFile(path, []byte("changed owned partial evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			r := recovery{store: s, mounts: func() ([]string, error) {
				if variant == "mount" {
					return []string{filepath.Join(s.root, ".transaction/nested")}, nil
				}
				return []string{}, nil
			}, run: func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
				t.Fatal("foreign orphan caused command")
				return nil, nil
			}}
			if err = r.restore(context.Background(), planned, nil); err == nil {
				t.Fatal("foreign/changed orphan removed", variant)
			}
			if _, err = os.Stat(filepath.Join(s.root, ".transaction")); err != nil {
				t.Fatal("evidence lost", err)
			}
		})
	}
}

func TestOrphanModuleRecoveryPlanStillRequiresFingerprintConfirmation(t *testing.T) {
	s := fixtureLifecycle(t)
	if err := os.Mkdir(filepath.Join(s.root, ".transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	first, err := s.prepare(context.Background(), "module.recover", map[string]any{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if first.target != "modules" || first.fingerprint == "" {
		t.Fatal(first)
	}
	if err = os.WriteFile(filepath.Join(s.root, ".transaction/.panasms-abcd123_"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := s.prepare(context.Background(), "module.recover", map[string]any{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if first.fingerprint == second.fingerprint {
		t.Fatal("changed orphan not bound to a new plan")
	}
}
