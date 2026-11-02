package networkmounts

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"panasms.local/backend/internal/systemops/folders"
	"path/filepath"
)

func pinDirectory(path string) (*os.File, error) { return folders.OpenDirectory(path) }
func unmountPinned(point string, expected folders.LiveMount) error {
	parent, err := pinDirectory(filepath.Dir(point))
	if err != nil {
		return err
	}
	defer parent.Close()
	leaf := filepath.Base(point)
	if leaf == "." || leaf == "/" || leaf == ".." {
		return reject("Invalid mount point")
	}
	fd, err := unix.Openat(int(parent.Fd()), leaf, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	target := os.NewFile(uintptr(fd), point)
	rows, err := folders.ReadMounts()
	if err != nil {
		target.Close()
		return err
	}
	actual, err := folders.DirectoryMount(target, rows)
	if err != nil {
		target.Close()
		return err
	}
	containing, err := folders.DirectoryMount(parent, rows)
	target.Close()
	if err != nil {
		return err
	}
	if actual != expected || actual.ID == containing.ID {
		return reject("The mount changed; review a new operation plan")
	}
	// Pin only the parent: retaining a reference to the mounted root makes normal unmount busy.
	// A mounted leaf cannot be renamed by an unprivileged caller; NOFOLLOW rejects a replacement link.
	return unix.Unmount(fmt.Sprintf("/proc/self/fd/%d/%s", parent.Fd(), leaf), unix.UMOUNT_NOFOLLOW)
}
func detachedMount(stage string) (*os.File, error) {
	fd, err := unix.OpenTree(unix.AT_FDCWD, stage, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), stage), nil
}
func attachMount(tree, target *os.File) error {
	return unix.MoveMount(int(tree.Fd()), "", int(target.Fd()), "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH)
}
