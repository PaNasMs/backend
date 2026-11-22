package modulelifecycle

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const sourceAddAttribute = "user.panasms-source-add"

// The marker follows the replacement inode across rename and restart. An
// independent edit can contain the exact planned rows without committing this add.
func (c catalogService) sourceAddCommitted(dir *os.File, id string) (bool, error) {
	fd, err := unix.Openat(int(dir.Fd()), filepath.Base(c.config), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	var value [64]byte
	n, err := unix.Fgetxattr(fd, sourceAddAttribute, value[:])
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ERANGE) {
		return false, nil
	}
	return err == nil && string(value[:n]) == id, err
}

func (c catalogService) finishSourceAdd(dir *os.File, change sourceChange) error {
	nonce, parseErr := hex.DecodeString(change.AddID)
	if !change.Add || parseErr != nil || len(nonce) != 16 || len(change.Keys) > 1 || len(change.Retired) != 0 {
		return reject("Invalid module repository journal")
	}
	for signer, raw := range change.Keys {
		if !signerPattern.MatchString(signer) || strings.HasPrefix(signer, "panasms-") {
			return reject("Invalid module repository publisher")
		}
		if _, err := discoveryKey(raw); err != nil {
			return err
		}
	}
	config, err := trustedDirectory(filepath.Dir(c.config), c.owner)
	if err != nil {
		return err
	}
	defer config.Close()
	if err := config.Sync(); err != nil {
		return err
	}
	committed, err := c.sourceAddCommitted(config, change.AddID)
	if err != nil {
		return err
	}
	if !committed {
		for signer := range change.Keys {
			if err := c.holdFailedAdd(dir, signer); err != nil {
				return err
			}
		}
		if c.sourceBoundary != nil {
			if err := c.sourceBoundary("rollback-sync"); err != nil {
				return err
			}
		}
		if err := dir.Sync(); err != nil {
			return err
		}
		return unlinkCatalogFile(dir, sourceIntent)
	}
	rows, err := c.sources()
	if err != nil {
		return err
	}
	if sourceState(rows) != change.After {
		return reject("Module repository configuration changed during recovery")
	}
	for _, src := range sourceSpecs(rows) {
		if src.ID != change.ID {
			continue
		}
		if src.Fingerprint != "" && len(src.Signers) == 1 {
			signer := src.Signers[0]
			if len(change.Keys) != 0 && change.Keys[signer] == nil {
				return reject("Invalid module repository journal")
			}
			if err := c.confirmSourceAddKey(signer, src.Fingerprint, change.Keys[signer]); err != nil {
				return err
			}
			if err := c.clearFailedAdd(dir, signer); err != nil {
				return err
			}
		} else if len(change.Keys) != 0 {
			return reject("Invalid module repository journal")
		}
		return unlinkCatalogFile(dir, sourceIntent)
	}
	return reject("Invalid module repository journal")
}

func (c catalogService) confirmSourceAddKey(signer, fingerprint string, staged []byte) error {
	if len(staged) != 0 {
		key, err := discoveryKey(staged)
		if err != nil || publicFingerprint(key) != fingerprint {
			return reject("Repository signing key changed")
		}
		if err := os.Mkdir(c.keys, 0755); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
		parent, err := trustedDirectory(filepath.Dir(c.keys), c.owner)
		if err != nil {
			return err
		}
		defer parent.Close()
		if err := parent.Sync(); err != nil {
			return err
		}
	}
	keys, err := trustedDirectory(c.keys, c.owner)
	if err != nil {
		return err
	}
	defer keys.Close()
	name := signer + ".pem"
	if len(staged) != 0 {
		err = atomicWriteAt(keys, name, staged, 0644, c.owner, uint32(os.Getegid()), "", true)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
	}
	live, err := readOwnedAt(keys, name, c.owner, 8192)
	if err != nil {
		return err
	}
	key, err := discoveryKey(live)
	if err != nil || publicFingerprint(key) != fingerprint {
		return reject("Repository signing key changed")
	}
	return keys.Sync()
}
