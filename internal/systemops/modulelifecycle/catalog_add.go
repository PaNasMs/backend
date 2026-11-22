package modulelifecycle

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"panasms.local/backend/internal/systemops"
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

func (c catalogService) recordSourceAddCommit(dir *os.File, change *sourceChange) error {
	change.AddCommitted = true
	raw, err := json.Marshal(change)
	if err != nil {
		return err
	}
	if len(raw) > maxSourceState {
		return reject("Module repository journal is too large")
	}
	return atomicAt(dir, sourceIntent, raw, 0600, c.owner)
}

var errSourceAddFenced = reject("Repository publisher remains inactive. Review the local key and enroll the repository again")

func (c catalogService) discardSourceAdd(dir *os.File, change sourceChange) error {
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

func (c catalogService) finishSourceAdd(dir *os.File, change sourceChange) error {
	nonce, parseErr := hex.DecodeString(change.AddID)
	if !archiveDigest.MatchString(change.AddedRow) || !change.Add || parseErr != nil || len(nonce) != 16 || len(change.Keys) > 1 || len(change.Retired) != 0 {
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
	if !change.AddCommitted {
		committed, err := c.sourceAddCommitted(config, change.AddID)
		if err != nil {
			return err
		}
		if !committed {
			return c.discardSourceAdd(dir, change)
		}
		if err := c.recordSourceAddCommit(dir, &change); err != nil {
			return err
		}
	}
	rows, err := c.sources()
	if err != nil {
		return err
	}
	for i, src := range sourceSpecs(rows) {
		if src.ID != change.ID || sourceState(rows[i:i+1]) != change.AddedRow {
			continue
		}
		if src.Fingerprint != "" && len(src.Signers) == 1 {
			signer := src.Signers[0]
			if strings.HasPrefix(signer, "panasms-") || !signerPattern.MatchString(signer) || (len(change.Keys) != 0 && change.Keys[signer] == nil) {
				return reject("Invalid module repository journal")
			}
			err := c.confirmSourceAddKey(signer, src.Fingerprint, change.Keys[signer])
			if err == nil {
				err = c.clearFailedAdd(dir, signer)
			}
			if errors.Is(err, errForeignPublisherHold) || errors.Is(err, errSourceAddFenced) {
				if cleanup := c.discardSourceAdd(dir, change); cleanup != nil {
					return cleanup
				}
				return errSourceAddFenced
			}
			if err != nil {
				return err
			}
		} else if len(change.Keys) != 0 {
			return reject("Invalid module repository journal")
		}
		return unlinkCatalogFile(dir, sourceIntent)
	}
	return c.discardSourceAdd(dir, change)
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
		var rejected *systemops.Rejected
		if errors.As(err, &rejected) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENXIO) {
			return errSourceAddFenced
		}
		return err
	}
	key, err := discoveryKey(live)
	if err != nil || publicFingerprint(key) != fingerprint {
		return errSourceAddFenced
	}
	return keys.Sync()
}
