package networkmounts

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"panasms.local/backend/internal/systemops/folders"
	"path/filepath"
	"strings"
	"testing"
)

func TestMountPrimitivesVM(t *testing.T) {
	uuid := strings.ToLower(os.Getenv("PANASMS_TEST_VM_UUID"))
	if os.Getenv("PANASMS_GO07_VM_PRIMITIVES") != "1" {
		t.Skip("disposable VM mount-namespace acceptance only")
	}
	raw, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil || uuid == "" || strings.TrimSpace(strings.ToLower(string(raw))) != uuid || os.Geteuid() != 0 {
		t.Fatal("wrong disposable VM")
	}
	self, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	init, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil || self == init {
		t.Fatal("private mount namespace required")
	}
	if err = unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	parent := filepath.Join(root, "parent")
	point := filepath.Join(parent, "target")
	moved := parent + "-moved"
	control := point
	for _, path := range []string{stage, parent, point} {
		if err = os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	mounted := map[string]bool{}
	defer func() {
		for _, path := range []string{filepath.Join(moved, "target"), point, stage} {
			if mounted[path] {
				if err := unix.Unmount(path, 0); err != nil {
					t.Errorf("normal cleanup %s: %v", path, err)
				}
			}
		}
	}()
	if err = unix.Mount("go07-stage", stage, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID, "size=4m"); err != nil {
		t.Fatal(err)
	}
	mounted[stage] = true
	if err = os.WriteFile(filepath.Join(stage, "proof"), []byte("selected"), 0600); err != nil {
		t.Fatal(err)
	}
	target, err := folders.OpenDirectory(point)
	if err != nil {
		t.Fatal(err)
	}
	persisted := uint64(0)
	id, err := attachStaged(stage, target, func(id uint64) error { persisted = id; return nil })
	target.Close()
	if err != nil {
		t.Fatal(err)
	}
	mounted[stage] = false
	mounted[point] = true
	if id == 0 || persisted != id {
		t.Fatal(id, persisted)
	}
	readMount := func(path string) folders.LiveMount {
		t.Helper()
		rows, err := folders.ReadMounts()
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.Target == path {
				return row
			}
		}
		t.Fatalf("missing mount %s", path)
		return folders.LiveMount{}
	}
	selected := readMount(point)
	if selected.ID != id {
		t.Fatal(selected, id)
	}
	proof, err := os.ReadFile(filepath.Join(point, "proof"))
	if err != nil || string(proof) != "selected" {
		t.Fatal(string(proof), err)
	}
	busy, err := os.Open(filepath.Join(point, "proof"))
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	err = unmountPinned(point, selected)
	if !errors.Is(err, unix.EBUSY) {
		busy.Close()
		t.Fatalf("busy mount changed: %v", err)
	}
	if readMount(point).ID != id {
		t.Fatal("busy identity changed")
	}
	busy.Close()
	t.Log("PASS detached attachment and normal busy-unmount preservation")
	err = unmountPinnedWith(point, selected, func() error {
		if err := os.Rename(parent, moved); err != nil {
			return err
		}
		mounted[point] = false
		mounted[filepath.Join(moved, "target")] = true
		if err := os.MkdirAll(control, 0700); err != nil {
			return err
		}
		if err := unix.Mount("go07-control", control, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID, "size=4m"); err != nil {
			return err
		}
		mounted[control] = true
		return os.WriteFile(filepath.Join(control, "proof"), []byte("unrelated preserved"), 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	mounted[filepath.Join(moved, "target")] = false
	proof, err = os.ReadFile(filepath.Join(control, "proof"))
	if err != nil || string(proof) != "unrelated preserved" {
		t.Fatal(string(proof), err)
	}
	rows, err := folders.ReadMounts()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ID == id {
			t.Fatal("selected mount remained", row)
		}
	}
	t.Log("PASS pinned-parent rename race removed only selected mount")
	link := filepath.Join(root, "link")
	if err = os.Symlink(control, link); err != nil {
		t.Fatal(err)
	}
	if err = unmountPinned(link, readMount(control)); err == nil {
		t.Fatal("symlink leaf accepted")
	}
	proof, err = os.ReadFile(filepath.Join(control, "proof"))
	if err != nil || string(proof) != "unrelated preserved" {
		t.Fatal(string(proof), err)
	}
	if err = unmountPinned(control, readMount(control)); err != nil {
		t.Fatal(err)
	}
	mounted[control] = false
	t.Log("PASS symlink leaf refusal and ordinary final unmount; no force or lazy flags")
}
