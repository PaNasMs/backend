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

func failedAddRecord(signer string) string {
	return "panasms source-add hold v1\n" + signer + "\n"
}

// A hold survives journal cleanup, including when an independently installed PEM
// occupies the key path. Only a later committed source-add releases it.
func (s store) hasFailedAdd(dir *os.File, signer string) (bool, error) {
	if !signerPattern.MatchString(signer) {
		return false, reject("Invalid module repository publisher")
	}
	expected := failedAddRecord(signer)
	raw, stat, err := readOwnedSnapshotAt(dir, failedAddName(signer), s.owner, int64(len(expected)))
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if string(raw) != expected || stat.Mode&07777 != 0600 {
		return false, reject("Unexpected file at the module publisher hold path")
	}
	return true, nil
}

func (c catalogService) holdFailedAdd(dir *os.File, signer string) error {
	held, err := c.hasFailedAdd(dir, signer)
	if err != nil {
		return err
	}
	if held {
		return dir.Sync()
	}
	return atomicWriteAt(dir, failedAddName(signer), []byte(failedAddRecord(signer)), 0600, c.owner, uint32(os.Getegid()), "", true)
}

func (c catalogService) clearFailedAdd(dir *os.File, signer string) error {
	held, err := c.hasFailedAdd(dir, signer)
	if err != nil {
		return err
	}
	if !held {
		return dir.Sync()
	}
	return unlinkCatalogFile(dir, failedAddName(signer))
}

func (s lifecycle) activePublisherKey(signer string) (ed25519.PublicKey, error) {
	dir, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	held, err := s.hasFailedAdd(dir, signer)
	if err != nil {
		return nil, err
	}
	if held {
		return nil, reject("Review and add the repository before trusting this publisher: " + signer)
	}
	return readPublicKey(s.keys, signer, s.owner)
}
