package modulelifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

func (s store) lock(ctx context.Context, reporter *systemops.Reporter) (*os.File, error) {
	directory, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), ".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "module lifecycle lock")
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err == nil && (stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != s.owner || stat.Nlink != 1 || stat.Mode&0777 != 0600) {
		err = reject("Module lifecycle lock permissions are unsafe")
	}
	if err == nil {
		err = directory.Sync()
	}
	if err == nil {
		err = waitLifecycleLock(ctx, file, reporter)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func waitLifecycleLock(ctx context.Context, file *os.File, reporter *systemops.Reporter) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if reporter != nil {
			if err := reporter.Checkpoint(); err != nil {
				return err
			}
		}
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
		if !time.Now().Before(deadline) {
			return reject("Module maintenance in progress; retry shortly")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

type maintenanceLease struct {
	file  *os.File
	path  string
	owner uint32
}

func acquireMaintenance(path string, owner uint32) (*maintenanceLease, error) {
	lease, err := openMaintenance(path, owner)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lease.file.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		lease.file.Close()
		return nil, reject("System maintenance in progress; retry after the update")
	}
	return lease, nil
}

func openMaintenance(path string, owner uint32) (*maintenanceLease, error) {
	directory, err := trustedDirectoryMode(filepath.Dir(path), owner, true)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "module system maintenance lock")
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err == nil && (stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != owner || stat.Nlink != 1 || stat.Mode&0022 != 0) {
		err = reject("System maintenance lock permissions are unsafe")
	}
	if err != nil {
		file.Close()
		return nil, reject("System maintenance in progress; retry after the update")
	}
	return &maintenanceLease{file: file, path: path, owner: owner}, nil
}

// A failed upgrade may have released SH. Callers must abandon staging and must
// not alter the registry, installed payloads or services unless EX succeeded.
func (lease *maintenanceLease) critical() error {
	directory, err := trustedDirectoryMode(filepath.Dir(lease.path), lease.owner, true)
	if err != nil {
		return err
	}
	defer directory.Close()
	var opened, current unix.Stat_t
	if err = unix.Fstat(int(lease.file.Fd()), &opened); err != nil {
		return err
	}
	if err = unix.Fstatat(int(directory.Fd()), filepath.Base(lease.path), &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if opened.Dev != current.Dev || opened.Ino != current.Ino || current.Uid != lease.owner || current.Nlink != 1 || current.Mode&unix.S_IFMT != unix.S_IFREG || current.Mode&0022 != 0 {
		return reject("System maintenance lock changed; retry after the update")
	}
	if err = unix.Flock(int(lease.file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return reject("Active requests or tasks prevent module maintenance; wait and retry")
	}
	return nil
}
