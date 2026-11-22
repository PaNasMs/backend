package modulelifecycle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const publisherHoldPrefix = ".source-add-hold-"

func holdPrefix(signer string) string {
	return publisherHoldPrefix + signer + "."
}

const (
	publisherHeld       byte = 'H'
	publisherReleased   byte = 'R'
	publisherCheckWrite byte = '?'
)

func failedAddRecord(name string, state byte) string {
	return string(state) + " panasms source-add hold v1\n" + name + "\n"
}

var errForeignPublisherHold = reject("An unrelated file occupies the module publisher hold path")

// Zero reads the record. publisherCheckWrite opens it read/write without updating it.
// A state change writes through the same
// descriptor that supplied the validated record, preserving replacements at the path.
func (s store) publisherHoldAt(dir *os.File, name string, transition byte) (byte, error) {
	var entry unix.Stat_t
	dirFD := int(dir.Fd())
	if err := unix.Fstatat(dirFD, name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return 0, err
	}
	expected := failedAddRecord(name, publisherHeld)
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
	if transition == publisherHeld || transition == publisherReleased {
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
	return errors.Is(err, errForeignPublisherHold) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EROFS) || errors.Is(err, unix.ETXTBSY)
}

func publisherHoldNames(dir *os.File, signer string) ([]string, error) {
	if !signerPattern.MatchString(signer) {
		return nil, reject("Invalid module repository publisher")
	}
	return sourceRecordNames(dir, holdPrefix(signer))
}

func stateDirectoryNames(dir *os.File) ([]string, error) {
	// A fresh descriptor starts enumeration at offset zero on every retry.
	fd, err := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	list := os.NewFile(uintptr(fd), dir.Name())
	defer list.Close()
	return list.Readdirnames(-1)
}

func sourceRecordNames(dir *os.File, prefix string) ([]string, error) {
	names, err := stateDirectoryNames(dir)
	if err != nil {
		return nil, err
	}
	var matches []string
	for _, name := range names {
		if suffix, ok := strings.CutPrefix(name, prefix); ok && sourceAddID.MatchString(suffix) {
			matches = append(matches, name)
		}
	}
	return matches, nil
}

func (c catalogService) holdFailedAdd(dir *os.File, signer string) error {
	names, err := publisherHoldNames(dir, signer)
	if err != nil {
		return err
	}
	for _, name := range names {
		if _, err := c.publisherHoldAt(dir, name, publisherHeld); err == nil {
			return dir.Sync()
		} else if !foreignPublisherHold(err) {
			return err
		}
	}
	// Occupied names belong to the operator. The new hold must survive even
	// when every one of those entries is subsequently moved aside.
	for {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		name := holdPrefix(signer) + hex.EncodeToString(nonce[:])
		raw := []byte(failedAddRecord(name, publisherHeld))
		err := c.writeSourceAddRecord(dir, name, raw, true)
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
	}
}

func (c catalogService) clearFailedAdd(dir *os.File, signer string) error {
	names, err := publisherHoldNames(dir, signer)
	if err != nil {
		return err
	}
	for _, name := range names {
		state, err := c.publisherHoldAt(dir, name, 0)
		if err == nil && state == publisherReleased {
			continue
		}
		if err == nil {
			_, err = c.publisherHoldAt(dir, name, publisherReleased)
		}
		if foreignPublisherHold(err) {
			if err := c.holdFailedAdd(dir, signer); err != nil {
				return err
			}
			return errForeignPublisherHold
		}
		if err != nil {
			return err
		}
	}
	return dir.Sync()
}

func (s lifecycle) publisherFenced(signer string) (bool, error) {
	dir, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	claims, err := publisherClaims(dir)
	if err != nil {
		return false, err
	}
	for _, claimed := range claims {
		if claimed == signer {
			return true, nil
		}
	}
	names, err := publisherHoldNames(dir, signer)
	if err != nil {
		return false, err
	}
	for _, name := range names {
		state, err := s.publisherHoldAt(dir, name, 0)
		if foreignPublisherHold(err) || state == publisherHeld {
			return true, nil
		}
		if err != nil {
			return false, err
		}
	}
	return false, nil
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
