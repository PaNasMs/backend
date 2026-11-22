package modulelifecycle

import (
	"crypto/ed25519"
	"errors"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func failedAddName(signer string) string {
	return ".source-add-hold-" + signer
}

const (
	publisherHeld     byte = 'H'
	publisherReleased byte = 'R'
)

func failedAddRecord(signer string, state byte) string {
	return string(state) + " panasms source-add hold v1\n" + signer + "\n"
}

var errForeignPublisherHold = reject("An unrelated file occupies the module publisher hold path")

// A zero transition reads the record. A state change writes through the same
// descriptor that supplied the validated record, preserving replacements at the path.
func (s store) publisherHoldAt(dir *os.File, name, signer string, transition byte) (byte, error) {
	if !signerPattern.MatchString(signer) {
		return 0, reject("Invalid module repository publisher")
	}
	var entry unix.Stat_t
	dirFD := int(dir.Fd())
	if err := unix.Fstatat(dirFD, name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return 0, err
	}
	expected := failedAddRecord(signer, publisherHeld)
	if entry.Mode != unix.S_IFREG|0600 || entry.Uid != s.owner || entry.Nlink != 1 || entry.Size != int64(len(expected)) {
		return 0, errForeignPublisherHold
	}
	access := unix.O_RDONLY
	if transition != 0 {
		access = unix.O_RDWR
	}
	fd, err := unix.Openat(dirFD, name, access|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return 0, err
	}
	if opened.Dev != entry.Dev || opened.Ino != entry.Ino || opened.Ctim != entry.Ctim || opened.Mode != entry.Mode ||
		opened.Uid != s.owner || opened.Nlink != 1 || opened.Size != entry.Size {
		return 0, unix.EAGAIN
	}
	raw := make([]byte, len(expected))
	if _, err := file.ReadAt(raw, 0); err != nil {
		return 0, err
	}
	state := raw[0]
	if (state != publisherHeld && state != publisherReleased) || string(raw[1:]) != expected[1:] {
		return 0, errForeignPublisherHold
	}
	if transition != 0 {
		if state != transition {
			if _, err := file.WriteAt([]byte{transition}, 0); err != nil {
				return 0, err
			}
			state = transition
		}
		if err := file.Sync(); err != nil {
			return 0, err
		}
	}
	var live unix.Stat_t
	if err := unix.Fstatat(dirFD, name, &live, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return 0, err
	}
	if live.Dev != opened.Dev || live.Ino != opened.Ino || live.Mode != opened.Mode || live.Uid != s.owner ||
		live.Nlink != 1 || live.Size != opened.Size {
		return 0, unix.EAGAIN
	}
	return state, nil
}

func foreignPublisherHold(err error) bool {
	return errors.Is(err, errForeignPublisherHold) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.ELOOP)
}

func (c catalogService) setPublisherHold(dir *os.File, name, signer string) error {
	_, err := c.publisherHoldAt(dir, name, signer, publisherHeld)
	if errors.Is(err, unix.ENOENT) {
		record := []byte(failedAddRecord(signer, publisherHeld))
		err = atomicWriteAt(dir, name, record, 0600, c.owner, uint32(os.Getegid()), true)
		if errors.Is(err, unix.EEXIST) {
			_, err = c.publisherHoldAt(dir, name, signer, publisherHeld)
		}
	}
	return err
}

// Recovery owns a separate record if the ordinary hold path is occupied. Moving
// aside an operator's file then leaves the publisher inactive until confirmation.
func reserveHoldDirectory(dir *os.File, signer string, owner uint32, create bool) (*os.File, error) {
	name := ".source-add-reserve-" + signer
	if create {
		return createDirectoryAt(dir, name, 0700, owner, false)
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Uid != owner || st.Mode&0022 != 0 {
		unix.Close(fd)
		return nil, errForeignPublisherHold
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (c catalogService) holdFailedAdd(dir *os.File, signer string) error {
	err := c.setPublisherHold(dir, failedAddName(signer), signer)
	if !foreignPublisherHold(err) {
		if err != nil {
			return err
		}
		return dir.Sync()
	}
	reserve, err := reserveHoldDirectory(dir, signer, c.owner, true)
	if err != nil {
		return err
	}
	defer reserve.Close()
	names, err := reserve.Readdirnames(-1)
	if err != nil {
		return err
	}
	for slot := 0; slot <= len(names); slot++ {
		name := strconv.Itoa(slot)
		err := c.setPublisherHold(reserve, name, signer)
		if foreignPublisherHold(err) {
			var stat unix.Stat_t
			if unix.Fstatat(int(reserve.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW) == nil {
				continue
			}
		}
		if err != nil {
			return err
		}
		if err := reserve.Sync(); err != nil {
			return err
		}
		return dir.Sync()
	}
	return unix.EAGAIN
}

func (s store) reservePublisherState(dir *os.File, signer string, transition byte) (bool, error) {
	reserve, err := reserveHoldDirectory(dir, signer, s.owner, false)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if foreignPublisherHold(err) || errors.Is(err, unix.ENOTDIR) {
		return true, errForeignPublisherHold
	}
	if err != nil {
		return false, err
	}
	defer reserve.Close()
	names, err := reserve.Readdirnames(-1)
	if err != nil {
		return false, err
	}
	for _, name := range names {
		state, err := s.publisherHoldAt(reserve, name, signer, 0)
		if foreignPublisherHold(err) {
			return true, errForeignPublisherHold
		}
		if err != nil {
			return false, err
		}
		if transition == 0 && state == publisherHeld {
			return true, nil
		}
	}
	if transition == publisherReleased {
		for _, name := range names {
			if _, err := s.publisherHoldAt(reserve, name, signer, publisherReleased); err != nil {
				if foreignPublisherHold(err) {
					return true, errForeignPublisherHold
				}
				return false, err
			}
		}
	}
	return false, nil
}

func (c catalogService) clearFailedAdd(dir *os.File, signer string) error {
	_, err := c.publisherHoldAt(dir, failedAddName(signer), signer, publisherReleased)
	if err == nil || errors.Is(err, unix.ENOENT) {
		_, err = c.reservePublisherState(dir, signer, publisherReleased)
	}
	if foreignPublisherHold(err) {
		// Re-enrollment can reuse an existing PEM, with no key in its journal
		// to drive a subsequent rollback. Preserve the fence before reporting it.
		if err := c.holdFailedAdd(dir, signer); err != nil {
			return err
		}
		return errForeignPublisherHold
	}
	if err != nil {
		return err
	}
	return dir.Sync()
}

func (s lifecycle) publisherFenced(signer string) (bool, error) {
	dir, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	state, err := s.publisherHoldAt(dir, failedAddName(signer), signer, 0)
	if foreignPublisherHold(err) || state == publisherHeld {
		return true, nil
	}
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return false, err
	}
	held, err := s.reservePublisherState(dir, signer, 0)
	if foreignPublisherHold(err) {
		return true, nil
	}
	return held, err
}

func (s lifecycle) activePublisherKey(signer string) (ed25519.PublicKey, error) {
	held, err := s.publisherFenced(signer)
	if err != nil {
		return nil, err
	}
	if held {
		return nil, reject("Review and add the repository before trusting this publisher: " + signer)
	}
	return readPublicKey(s.keys, signer, s.owner)
}
