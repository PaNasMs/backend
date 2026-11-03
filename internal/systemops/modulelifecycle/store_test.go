package modulelifecycle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func fixtureStore(t *testing.T) store {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	return store{root: root, owner: uint32(os.Geteuid())}
}

func TestRegistryPersistenceAndMemberQueryPreserveMetadata(t *testing.T) {
	s := fixtureStore(t)
	registry, err := s.registry()
	if err != nil || len(registry) != 0 {
		t.Fatal(registry, err)
	}
	registry = Registry{
		"files":   {"id": "files", "enabled": false, "future": map[string]any{"counter": json.Number("9007199254740993")}},
		"member":  {"id": "member", "memberAccess": true, "dependencies": map[string]any{"files": ">=0.1.0"}},
		"private": {"id": "private", "enabled": true},
	}
	if err = s.saveRegistry(registry); err != nil {
		t.Fatal(err)
	}
	got, err := s.registry()
	if err != nil || !reflect.DeepEqual(got, registry) {
		t.Fatal(got, err)
	}
	query, err := listModules(got, "0.2.34", true)
	if err != nil {
		t.Fatal(err)
	}
	items := query["installed"].([]Manifest)
	if len(items) != 2 || items[0]["id"] != "files" || items[1]["id"] != "member" || !reflect.DeepEqual(items[0]["requiredBy"], []string{"member"}) {
		t.Fatal(query)
	}
	items[0]["future"].(map[string]any)["counter"] = "modified"
	if got["files"]["future"].(map[string]any)["counter"] != json.Number("9007199254740993") {
		t.Fatal("query mutated registry")
	}
	admin, err := listModules(got, "0.2.34", false)
	if err != nil || len(admin["installed"].([]Manifest)) != 3 {
		t.Fatal(admin, err)
	}
	info, _ := os.Stat(filepath.Join(s.root, "registry.json"))
	if info.Mode().Perm() != 0644 {
		t.Fatal(info.Mode())
	}
}

func TestRegistryRejectsUntrustedReplacementWithoutOverwriting(t *testing.T) {
	for _, variant := range []string{"symlink", "hardlink", "writable", "fifo", "parent-link", "parent-writable", "corrupt", "oversize"} {
		t.Run(variant, func(t *testing.T) {
			s := fixtureStore(t)
			path := filepath.Join(s.root, "registry.json")
			if err := os.WriteFile(path, []byte(`{}`), 0644); err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "symlink":
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".saved", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".linked"); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(s.root, link); err != nil {
					t.Fatal(err)
				}
				s.root = link
			case "parent-writable":
				if err := os.Chmod(s.root, 0777); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(path, []byte(`{"broken":`), 0644); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate((8 << 20) + 1)
				file.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.registry(); err == nil {
				t.Fatal("untrusted module registry accepted")
			}
			if variant == "symlink" || variant == "hardlink" || variant == "writable" || variant == "fifo" || variant == "parent-link" || variant == "parent-writable" {
				if err := s.saveRegistry(Registry{}); err == nil {
					t.Fatal("untrusted module registry overwritten")
				}
			}
		})
	}
}
