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

func sourceTrustState(src source) string {
	raw, _ := json.Marshal(src)
	return sourceDigest(raw)
}

func (c catalogService) recordSourceAddDecision(dir *os.File, change *sourceChange, decision string) error {
	change.AddDecision = decision
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

func (c catalogService) discardSourceAdd(dir, config *os.File, change sourceChange) error {
	if change.AddDecision != "aborted" {
		if err := c.recordSourceAddDecision(dir, &change, "aborted"); err != nil {
			return err
		}
	}
	if err := c.holdFailedAdd(dir, change.AddSigner); err != nil {
		return err
	}
	if c.sourceBoundary != nil {
		if err := c.sourceBoundary("rollback-sync"); err != nil {
			return err
		}
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	return c.retireSourceAdd(dir, config, change)
}

func (c catalogService) retireSourceAdd(dir, config *os.File, change sourceChange) error {
	if err := change.Stage.cleanup(config); err != nil {
		return err
	}
	return unlinkCatalogFile(dir, sourceIntent)
}

func (c catalogService) finishSourceAdd(dir *os.File, change sourceChange) error {
	nonce, parseErr := hex.DecodeString(change.AddID)
	if change.Stage == nil || change.AddID != change.Stage.ID || !signerPattern.MatchString(change.AddSigner) || strings.HasPrefix(change.AddSigner, "panasms-") || !archiveDigest.MatchString(change.AddedRow) || !change.Add || parseErr != nil || len(nonce) != 16 || len(change.Keys) > 1 || len(change.Retired) != 0 {
		return reject("Invalid module repository journal")
	}
	for signer, raw := range change.Keys {
		if signer != change.AddSigner {
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
	switch change.AddDecision {
	case "aborted":
		return c.discardSourceAdd(dir, config, change)
	case "":
		committed, err := change.Stage.committed(config)
		if err != nil {
			return err
		}
		if !committed {
			return c.discardSourceAdd(dir, config, change)
		}
		if err := c.recordSourceAddDecision(dir, &change, "committed"); err != nil {
			return err
		}
	case "committed":
	default:
		return reject("Invalid module repository journal")
	}
	rows, err := c.sources()
	if err != nil {
		return err
	}
	for _, src := range sourceSpecs(rows) {
		if src.ID != change.ID || sourceTrustState(src) != change.AddedRow {
			continue
		}
		if src.Fingerprint != "" && len(src.Signers) == 1 {
			signer := src.Signers[0]
			if signer != change.AddSigner {
				return reject("Invalid module repository journal")
			}
			err := c.confirmSourceAddKey(signer, src.Fingerprint, change.Keys[signer])
			if err == nil {
				err = c.clearFailedAdd(dir, signer)
			}
			if errors.Is(err, errForeignPublisherHold) || errors.Is(err, errSourceAddFenced) {
				if cleanup := c.discardSourceAdd(dir, config, change); cleanup != nil {
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
		if c.sourceBoundary != nil {
			if err := c.sourceBoundary("publisher-confirmed"); err != nil {
				return err
			}
		}
		return c.retireSourceAdd(dir, config, change)
	}
	return c.discardSourceAdd(dir, config, change)
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
		err = atomicWriteAt(keys, name, staged, 0644, c.owner, uint32(os.Getegid()), true)
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
