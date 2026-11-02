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
	return unmountPinnedWith(point, expected, nil)
}
func unmountPinnedWith(point string, expected folders.LiveMount, before func() error) error {
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
	var containing unix.Statx_t
	err = unix.Statx(int(parent.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &containing)
	target.Close()
	if err != nil {
		return err
	}
	if containing.Mask&unix.STATX_MNT_ID == 0 || containing.Mnt_id == 0 {
		return reject("The mount identity is unavailable")
	}
	if actual != expected || actual.ID == containing.Mnt_id {
		return reject("The mount changed; review a new operation plan")
	}
	// Pin only the parent: retaining a reference to the mounted root makes normal unmount busy.
	// A mounted leaf cannot be renamed by an unprivileged caller; NOFOLLOW rejects a replacement link.
	if before != nil {
		if err = before(); err != nil {
			return err
		}
	}
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

func attachStaged(stage string, target *os.File, before func(uint64) error) (uint64, error) {
	tree, err := detachedMount(stage)
	if err != nil {
		return 0, err
	}
	defer tree.Close()
	var info unix.Statx_t
	if err = unix.Statx(int(tree.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &info); err != nil {
		return 0, err
	}
	if info.Mask&unix.STATX_MNT_ID == 0 || info.Mnt_id == 0 {
		return 0, reject("The mount identity is unavailable")
	}
	if err = before(info.Mnt_id); err != nil {
		return 0, err
	}
	if err = unix.Unmount(stage, 0); err != nil {
		return 0, err
	}
	if err = attachMount(tree, target); err != nil {
		return 0, err
	}
	return info.Mnt_id, nil
}
