package modulelifecycle

import (
	"crypto/rand"
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
	return c.writeSourceAddRecord(dir, sourceIntent, raw, false)
}

var errSourceAddFenced = reject("The repository publisher is inactive. Review the local signing key, then add the repository again and confirm its fingerprint. Remove its existing entry first if still configured.")

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
	if change.KeyStage != nil {
		keys, err := trustedDirectory(c.keys, c.owner)
		if err == nil {
			defer keys.Close()
			if err = change.KeyStage.releaseKeyObservation(keys); err == nil {
				err = change.KeyStage.cleanup(keys)
			}
		}
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
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
	if stage := change.KeyStage; stage != nil && (stage.Owner != c.owner || !sourceAddID.MatchString(stage.ID) || stage.ID == change.AddID || stage.Before.Inode != 0) {
		return reject("Invalid module repository key stage")
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
	case "preparing", "aborted":
		return c.discardSourceAdd(dir, config, change)
	case "", "config-ready":
		if change.KeyBeforeConfig != (change.AddDecision == "config-ready") {
			return reject("Invalid module repository journal")
		}
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
	case "key-preparing":
		if change.KeyStage == nil || len(change.Keys) != 1 {
			return reject("Invalid module repository journal")
		}
	case "key-ready", "key-probing", "key-observed", "key-confirmed":
		if change.KeyStage == nil || len(change.Keys) != 0 || change.KeyStage.After.Inode == 0 {
			return reject("Invalid module repository journal")
		}
	default:
		return reject("Invalid module repository journal")
	}
	if change.KeyBeforeConfig {
		if change.AddDecision != "committed" {
			// A pre-commit key can already be public. Retain it under the
			// signer hold, including when it matches our private draft.
			return c.discardSourceAdd(dir, config, change)
		}
		if len(change.Keys) != 0 {
			return reject("Invalid module repository journal")
		}
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
			var err error
			if change.KeyBeforeConfig {
				err = c.verifySourceAddKey(signer, src.Fingerprint)
			} else {
				err = c.confirmSourceAddKey(dir, &change, src.Fingerprint)
			}
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

func (c catalogService) confirmSourceAddKey(dir *os.File, change *sourceChange, fingerprint string) error {
	signer := change.AddSigner
	staged := change.Keys[signer]
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
	if len(staged) == 0 && errors.Is(err, unix.ENOENT) {
		return errSourceAddFenced
	}
	if err != nil {
		return err
	}
	defer keys.Close()
	name := signer + ".pem"
	if len(staged) != 0 {
		if change.KeyStage != nil {
			if err := change.KeyStage.cleanup(keys); err != nil {
				return err
			}
		}
		blocked, err := keyStageBlockedAt(keys, c.owner)
		if err != nil {
			return err
		}
		if blocked {
			return errSourceAddFenced
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		draft := sourceAddStage{ID: hex.EncodeToString(nonce[:]), Owner: c.owner}
		draft, err = draft.writeDraft(keys, staged, 0644, func(s sourceAddStage) error {
			change.KeyStage = &s
			return c.recordSourceAddDecision(dir, change, "key-preparing")
		})
		if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
			return errSourceAddFenced
		}
		if err != nil {
			return err
		}
		if c.sourceBoundary != nil {
			if err := c.sourceBoundary("key-preparing"); err != nil {
				return err
			}
		}
		change.KeyStage = &draft
		change.Keys = nil
		if err := c.recordSourceAddDecision(dir, change, "key-ready"); err != nil {
			return err
		}
		if c.sourceBoundary != nil {
			if err := c.sourceBoundary("key-ready"); err != nil {
				return err
			}
		}
	}
	if change.AddDecision == "key-ready" {
		seen, err := change.KeyStage.legacyKeyObserved(keys)
		if err != nil {
			return err
		}
		if !seen {
			published, err := change.KeyStage.publishKey(keys, name, func() error {
				if c.sourceBoundary != nil {
					if err := c.sourceBoundary("key-publishing"); err != nil {
						return err
					}
				}
				// Only this call may rename. A restart in key-probing must
				// respect any withdrawal even if the draft is still present.
				return c.recordSourceAddDecision(dir, change, "key-probing")
			}, c.sourceBoundary)
			if err != nil {
				return err
			}
			if c.sourceBoundary != nil {
				phase := "key-exists"
				if published {
					phase = "key-published"
				}
				if err := c.sourceBoundary(phase); err != nil {
					return err
				}
			}
		}
		// A legacy journal may have a witness or a consumed private draft.
		if change.AddDecision == "key-ready" {
			if err := c.recordSourceAddDecision(dir, change, "key-probing"); err != nil {
				return err
			}
		}
	}
	if change.AddDecision == "key-probing" || change.AddDecision == "key-observed" {
		if err := change.KeyStage.releaseKeyObservation(keys); err != nil {
			return err
		}
	}
	if err := c.verifySourceAddKey(signer, fingerprint); err != nil {
		return err
	}
	if change.AddDecision == "key-probing" || change.AddDecision == "key-observed" {
		return c.recordSourceAddDecision(dir, change, "key-confirmed")
	}
	return nil
}

func (c catalogService) verifySourceAddKey(signer, fingerprint string) error {
	key, err := loadPublicKey(c.keys, signer, c.owner, true)
	if err != nil {
		var rejected *systemops.Rejected
		if errors.As(err, &rejected) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENXIO) {
			return errSourceAddFenced
		}
		return err
	}
	if publicFingerprint(key) != fingerprint {
		return errSourceAddFenced
	}
	return nil
}
