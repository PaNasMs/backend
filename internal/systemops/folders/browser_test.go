package folders

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedBrowserExcludesLinksAndHiddenAndNeverCreates(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"Visible", ".hidden", "lost+found", "Alpha"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "Visible"), filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	dir, err := openDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	entries, err := children(dir, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name != "Alpha" || entries[1].Name != "Visible" {
		t.Fatal(entries)
	}
	for _, path := range []string{filepath.Join(root, "linked"), filepath.Join(root, "missing"), filepath.Join(root, "linked", "child")} {
		if f, err := openDirectory(path); err == nil {
			f.Close()
			t.Fatalf("accepted %s", path)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "missing")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
func TestBrowserPinnedDirectoryDoesNotFollowReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "owned")
	os.Mkdir(path, 0700)
	os.Mkdir(filepath.Join(path, "original"), 0700)
	dir, err := openDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	os.Rename(path, path+"-moved")
	os.Mkdir(path, 0700)
	os.Mkdir(filepath.Join(path, "replacement"), 0700)
	rows, err := children(dir, path, nil)
	if err != nil || len(rows) != 1 || rows[0].Name != "original" {
		t.Fatal(rows, err)
	}
}
