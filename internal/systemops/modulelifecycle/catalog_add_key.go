package modulelifecycle

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
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
	if reserved.Mode&(unix.S_IFMT|0777) != unix.S_IFDIR|0700 || reserved.Uid != owner || reserved.Dev != parent.Dev {
		return true, nil
	}
	// Bind mounts can share a device number while rename still crosses mounts.
	var keyMount, draftMount unix.Statx_t
	err = unix.Statx(int(keys.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &keyMount)
	if err == nil {
		err = unix.Statx(int(keys.Fd()), sourceAddStageRoot, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &draftMount)
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return keyMount.Mask&draftMount.Mask&unix.STATX_MNT_ID != 0 && keyMount.Mnt_id != draftMount.Mnt_id, nil
}

// Earlier journals reserved a private .seen name and could have observed an
// operator's key there before recording their verify-only decision.
func (s sourceAddStage) legacyKeyObserved(keys *os.File) (bool, error) {
	if !s.SeenVacant {
		return false, nil
	}
	dir, err := s.open(keys)
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	if errors.Is(err, unix.ESTALE) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EACCES) {
		return false, errSourceAddFenced
	}
	if err != nil {
		return false, err
	}
	defer dir.Close()
	var entry unix.Stat_t
	err = unix.Fstatat(int(dir.Fd()), s.ID+".seen", &entry, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	return err == nil, err
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
