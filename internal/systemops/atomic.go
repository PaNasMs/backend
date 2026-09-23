package systemops

import (
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"time"
)

// BackupDir is where AtomicWrite copies the previous contents of a file before
// replacing it, matching the Python common.atomic backup location.
const BackupDir = "/var/lib/panasms-agent/backups"

// AtomicWrite replaces the file at path with text, reproducing the guarantees
// of backend/management/common.atomic:
//   - refuse to write through a symlink;
//   - create parent directories;
//   - copy any existing file to a timestamped 0600 backup first;
//   - write to a temp file in the same directory, fchmod it, fsync the data,
//     rename it into place, then fsync the parent directory so the rename is
//     durable.
//
// mode is the permission of the final file (Python default 0o600).
func AtomicWrite(path, text string, mode os.FileMode) error {
	return atomicWrite(path, text, mode, BackupDir)
}

// atomicWrite is AtomicWrite with an injectable backup directory so tests can
// exercise the backup path without writing under /var.
func atomicWrite(path, text string, mode os.FileMode, backupDir string) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return reject("The configuration is a symbolic link")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		if err := backup(path, backupDir); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".panasms-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Remove the temp file on any failure path; a successful rename makes the
	// later remove a harmless no-op.
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.WriteString(text); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	return fsyncDir(dir)
}

func backup(path, backupDir string) error {
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(fd), path)
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return reject("Configuration is not a regular file")
	}
	saved := filepath.Join(backupDir, fmt.Sprintf("%s.%d", filepath.Base(path), time.Now().UnixNano()))
	target, err := os.OpenFile(saved, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer target.Close()
	if _, err := io.Copy(target, source); err != nil {
		return err
	}
	if err := target.Sync(); err != nil {
		return err
	}
	if err := target.Close(); err != nil {
		return err
	}
	return fsyncDir(backupDir)
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
