package modulelifecycle

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

func keyStageBlockedAt(keys *os.File, owner uint32) (bool, error) {
	var parent, reserved unix.Stat_t
	if err := unix.Fstat(int(keys.Fd()), &parent); err != nil {
		return false, err
	}
	err := unix.Fstatat(int(keys.Fd()), sourceAddStageRoot, &reserved, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return reserved.Mode&(unix.S_IFMT|0777) != unix.S_IFDIR|0700 || reserved.Uid != owner || reserved.Dev != parent.Dev, nil
}

func (s sourceAddStage) reserveKeyObservation(keys *os.File) error {
	dir, err := s.open(keys)
	if err != nil {
		return err
	}
	defer dir.Close()
	var entry unix.Stat_t
	err = unix.Fstatat(int(dir.Fd()), s.ID+".seen", &entry, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return errSourceAddFenced
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

// Link the operator's entry without following it. The hard link records the
// observation even if the process stops before it can update the journal.
// ENOENT from this method means the private publication slot was consumed.
func (s sourceAddStage) observeExistingKey(keys *os.File, target string) (bool, error) {
	dir, err := s.open(keys)
	if errors.Is(err, unix.ESTALE) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EACCES) {
		return false, errSourceAddFenced
	}
	if err != nil {
		return false, err
	}
	defer dir.Close()
	if err := errors.Join(dir.Sync(), keys.Sync()); err != nil {
		return false, err
	}
	slot, _, err := sourceAddFileAt(dir, s.ID, s.Owner)
	var rejected *systemops.Rejected
	if errors.As(err, &rejected) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENXIO) {
		return false, errSourceAddFenced
	}
	if err != nil {
		return false, err
	}
	if slot.Inode == 0 {
		return false, unix.ENOENT
	}
	if slot != s.After || !s.SeenVacant {
		return false, errSourceAddFenced
	}
	seen := s.ID + ".seen"
	var entry unix.Stat_t
	err = unix.Fstatat(int(dir.Fd()), seen, &entry, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return false, err
	}
	err = unix.Linkat(int(keys.Fd()), target, int(dir.Fd()), seen, 0)
	switch {
	case err == nil, errors.Is(err, unix.EEXIST):
		return true, dir.Sync()
	case errors.Is(err, unix.ENOENT):
		return false, nil
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES), errors.Is(err, unix.EMLINK), errors.Is(err, unix.EXDEV):
		return false, errSourceAddFenced
	default:
		return false, err
	}
}

func (s sourceAddStage) releaseKeyObservation(keys *os.File) error {
	if !s.SeenVacant {
		return nil
	}
	dir, err := s.open(keys)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESTALE) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	return unlinkCatalogFile(dir, s.ID+".seen")
}
