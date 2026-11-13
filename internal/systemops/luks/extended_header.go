package luks

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
)

func headerDirectory(folder string) (*os.File, storagebase.TargetWitness, error) {
	if _, err := systemops.CleanPath(folder); err != nil {
		return nil, storagebase.TargetWitness{}, err
	}
	w, dir, err := storagebase.ObserveTarget(folder)
	if err != nil {
		return nil, w, err
	}
	if w.Ancestor != folder {
		dir.Close()
		return nil, w, reject("Select an existing folder without symbolic links")
	}
	return dir, w, nil
}

const headerLimit = 128 << 20

func snapshotHeader(ctx context.Context, dir *os.File, name, uuid string) (*os.File, string, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "", reject("LUKS header backup not found")
	}
	source := os.NewFile(uintptr(fd), name)
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > headerLimit {
		return nil, "", reject("Invalid LUKS header backup size or type")
	}
	cache, err := anonymousFile("luks-header")
	if err != nil {
		return nil, "", err
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(cache, hash), io.LimitReader(source, headerLimit+1))
	if err == nil && n != info.Size() {
		err = reject("The LUKS header backup changed")
	}
	if err == nil {
		err = sealFile(cache)
	}
	if err == nil {
		var meta luksMetadata
		meta, err = readLUKSMetadata(ctx, fdPath(cache))
		if err == nil && meta.UUID != uuid {
			err = reject("The backup belongs to another LUKS volume")
		} else if err == nil && len(meta.UsableSlots) == 0 {
			err = reject("The backup has no usable LUKS password slot")
		}
	}
	if err != nil {
		cache.Close()
		return nil, "", err
	}
	return cache, fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// Link the already-synced inode without replacing any existing destination.
// A pinned directory and fd-based source link keep the operation inside the
// selected directory even if somebody renames or replaces a visible path.
func publishFile(dir *os.File, name string, source io.Reader, uid, gid int) error {
	fd, err := unix.Openat(int(dir.Fd()), ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	var output *os.File
	if err == nil {
		output = os.NewFile(uintptr(fd), name)
	} else if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.EINVAL) {
		output, err = os.CreateTemp(fdPath(dir), ".panasms-luks-*")
		if err != nil {
			return err
		}
		defer os.Remove(output.Name())
	} else {
		return err
	}
	defer output.Close()
	if _, err = io.Copy(output, source); err != nil {
		return err
	}
	if uid >= 0 {
		if err = output.Chown(uid, gid); err != nil {
			return err
		}
	}
	if err = output.Sync(); err != nil {
		return err
	}
	if err = unix.Linkat(unix.AT_FDCWD, fdPath(output), int(dir.Fd()), name, unix.AT_SYMLINK_FOLLOW); err != nil {
		return err
	}
	return dir.Sync()
}

func executeHeader(ctx context.Context, action string, p *prepared, path string, s extraState, r *systemops.Reporter) error {
	folder := s.Folder.Ancestor
	dir, w, err := headerDirectory(folder)
	if err != nil {
		return err
	}
	defer dir.Close()
	if w != s.Folder {
		return reject("The backup folder changed; review a new operation plan")
	}
	name := p.UUID + ".luks-header"
	if action == "luks.header-restore" {
		f, digest, err := snapshotHeader(ctx, dir, name, p.UUID)
		if err != nil {
			return err
		}
		defer f.Close()
		if digest != s.HeaderHash {
			return reject("The header backup changed; review a new operation plan")
		}
		return cryptAction(ctx, []string{"luksHeaderRestore", "--batch-mode", "--header-backup-file", fdPath(f), path}, "", true, r)
	}
	if p.Actor.UID <= 0 || p.Actor.GID < 0 {
		return reject("The backup owner could not be verified")
	}
	// cryptsetup creates its backup file itself. A private tmpfs directory
	// isolates that pathname from the destination directory's owner.
	const work = "/run/panasms-luks-headers"
	if err := storagebase.SecureDirectory(work, 0, true); err != nil {
		return err
	}
	header := filepath.Join(work, "header")
	// The global storage lock serializes backups. Reap a partial header left by
	// a worker that died before it could unlink its scratch file.
	if err := os.Remove(header); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	defer os.Remove(header)
	if err = cryptAction(ctx, []string{"luksHeaderBackup", "--header-backup-file", header, path}, "", false, r); err != nil {
		return err
	}
	source, err := os.Open(header)
	if err != nil {
		return err
	}
	defer source.Close()
	if err = os.Remove(header); err != nil {
		return err
	}
	if err = storagebase.SameDirectory(dir, folder); err != nil {
		return err
	}
	return publishFile(dir, name, source, p.Actor.UID, p.Actor.GID)
}
