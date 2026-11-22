package modulelifecycle

import (
	"crypto/ed25519"
	"errors"
	"os"

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
func (s store) publisherHoldAt(dir *os.File, signer string, transition byte) (byte, error) {
	if !signerPattern.MatchString(signer) {
		return 0, reject("Invalid module repository publisher")
	}
	name := failedAddName(signer)
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

func (c catalogService) holdFailedAdd(dir *os.File, signer string) error {
	_, err := c.publisherHoldAt(dir, signer, publisherHeld)
	if errors.Is(err, unix.ENOENT) {
		record := []byte(failedAddRecord(signer, publisherHeld))
		err = atomicWriteAt(dir, failedAddName(signer), record, 0600, c.owner, uint32(os.Getegid()), "", true)
		if errors.Is(err, unix.EEXIST) {
			_, err = c.publisherHoldAt(dir, signer, publisherHeld)
		}
	}
	if err != nil && !errors.Is(err, errForeignPublisherHold) {
		return err
	}
	return dir.Sync()
}

func (c catalogService) clearFailedAdd(dir *os.File, signer string) error {
	_, err := c.publisherHoldAt(dir, signer, publisherReleased)
	if err != nil && !errors.Is(err, unix.ENOENT) {
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
	state, err := s.publisherHoldAt(dir, signer, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if errors.Is(err, errForeignPublisherHold) {
		return true, nil
	}
	return state == publisherHeld, err
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
