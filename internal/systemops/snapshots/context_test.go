package snapshots

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSingleDataMount(t *testing.T) {
	for _, tc := range []struct {
		fs     string
		points []any
		want   string
	}{
		{"btrfs", []any{nil, "/mnt/data"}, "/mnt/data"},
		{"ext4", []any{"/srv/data"}, ""},
		{"btrfs", []any{"/var/data"}, ""},
		{"btrfs", []any{"/mnt/a", "/mnt/b"}, ""},
		{"btrfs", []any{nil}, ""},
	} {
		got, err := mountpoint(map[string]any{"fstype": tc.fs, "mountpoints": tc.points})
		if tc.want == "" {
			if err == nil {
				t.Fatalf("accepted %s %v", tc.fs, tc.points)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatal(tc, got, err)
		}
	}
}

func TestManagedDirectoryNeverFollowsLink(t *testing.T) {
	root := t.TempDir()
	folder, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer folder.Close()
	v := volume{Root: folder}
	if _, err = v.openDirectory(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err = os.Symlink(t.TempDir(), filepath.Join(root, directoryName)); err != nil {
		t.Fatal(err)
	}
	if _, err = v.openDirectory(); !errors.Is(err, unix.ELOOP) {
		t.Fatal(err)
	}
}

func TestSnapshotEntryHasToBeAReadOnlySubvolume(t *testing.T) {
	p := t.TempDir()
	if err := os.Mkdir(filepath.Join(p, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("data", filepath.Join(p, "link")); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	v := volume{Directory: dir}
	for _, name := range []string{"data", "../data", "link", ".", "missing"} {
		if f, _, err := v.snapshot(name); err == nil {
			f.Close()
			t.Errorf("accepted %s", name)
		}
	}
}
