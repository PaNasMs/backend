package networkmounts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateIsPrivateBoundedAndPointBound(t *testing.T) {
	s, p := fixture(t)
	point := param(p, "point")
	state := &transaction{Schema: 1, Point: point, Source: "//nas/share", FSType: "cifs", Phase: "preparing"}
	if err := s.save(state); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(s.root)
	if info.Mode().Perm() != 0700 {
		t.Fatal(info.Mode())
	}
	path := filepath.Join(s.root, Key(point)+".json")
	info, _ = os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	loaded, err := s.load(point)
	if err != nil || loaded.Source != state.Source {
		t.Fatal(loaded, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "secret-value") {
		t.Fatal("secret persisted")
	}
	state.Point = point + "-other"
	raw = []byte(`{"schema":1,"point":"wrong","source":"//nas/share","fstype":"cifs","phase":"preparing"}`)
	os.WriteFile(path, raw, 0600)
	if _, err = s.load(point); err == nil {
		t.Fatal("mismatched state accepted")
	}
	os.WriteFile(path, make([]byte, 65537), 0600)
	if _, err = s.load(point); err == nil {
		t.Fatal("oversized state accepted")
	}
}
func TestStateRejectsLinksAndUnsafePermissions(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "writable", "root-symlink"} {
		t.Run(kind, func(t *testing.T) {
			s, p := fixture(t)
			point := param(p, "point")
			if kind == "root-symlink" {
				os.Symlink(t.TempDir(), s.root)
				if _, err := s.load(point); err == nil {
					t.Fatal("symlink root")
				}
				return
			}
			os.Mkdir(s.root, 0700)
			path := filepath.Join(s.root, Key(point)+".json")
			switch kind {
			case "symlink":
				os.Symlink(filepath.Join(t.TempDir(), "other"), path)
			case "hardlink":
				other := filepath.Join(s.root, "other")
				os.WriteFile(other, []byte("{}"), 0600)
				os.Link(other, path)
			case "writable":
				os.WriteFile(path, []byte("{}"), 0666)
				os.Chmod(path, 0666)
			}
			if _, err := s.load(point); err == nil {
				t.Fatal(kind)
			}
		})
	}
}
func TestStateLockSerializesOperations(t *testing.T) {
	s, _ := fixture(t)
	first, err := s.lock()
	if err != nil {
		t.Fatal(err)
	}
	if second, err := s.lock(); err == nil {
		second.Close()
		t.Fatal("second mutation admitted")
	}
	first.Close()
	last, err := s.lock()
	if err != nil {
		t.Fatal(err)
	}
	last.Close()
}
