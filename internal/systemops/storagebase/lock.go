package storagebase

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

var deviceName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func DeviceLock(ctx context.Context, target string) (*os.File, error) {
	if filepath.Dir(target) != "/dev" || !deviceName.MatchString(filepath.Base(target)) {
		return nil, reject("Select a block device")
	}
	return Lock(ctx, "/run/panasms-filesystems", filepath.Base(target)+".lock", 0)
}
func DomainLock(ctx context.Context) (*os.File, error) {
	return Lock(ctx, "/run/panasms-storage", "operation.lock", 0)
}

// Use the legacy filesystem lock inode, including existing root-owned0644 files.
// Never replace a lock file: Python and Go workers must serialize on the same inode.
func Lock(ctx context.Context, root, name string, owner int) (*os.File, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, reject("Invalid storage lock")
	}
	if err := SecureDirectory(root, owner, true); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(root, name), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	keep := false
	defer func() {
		if !keep {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	raw := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || int(raw.Uid) != owner || raw.Nlink != 1 {
		return nil, reject("Storage lock permissions are unsafe")
	}
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			keep = true
			return f, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			return nil, err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
func SecureDirectory(path string, owner int, create bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return reject("Storage state permissions are unsafe")
	}
	root, err := os.Stat("/")
	if err != nil {
		return err
	}
	rootUID := root.Sys().(*syscall.Stat_t).Uid
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil {
			return err
		}
		raw := st.Sys().(*syscall.Stat_t)
		sticky := raw.Uid == rootUID && st.Mode()&os.ModeSticky != 0
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (int(raw.Uid) != owner && raw.Uid != rootUID) || (st.Mode().Perm()&0022 != 0 && !sticky) {
			return reject("Storage state permissions are unsafe")
		}
		if current == "/" {
			break
		}
	}
	if create {
		if err = os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return err
		}
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0700 || int(st.Sys().(*syscall.Stat_t).Uid) != owner {
		return reject("Storage state permissions are unsafe")
	}
	return nil
}
