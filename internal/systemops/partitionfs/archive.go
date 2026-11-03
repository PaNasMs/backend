package partitionfs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
)

const archiveAction = "storage.archive-journal"
const archiveWarning = "Archiving preserves the interrupted journal and allows new plans. Inspect the disk and mount configuration before confirming."

var useConfigurationRecovery = reject("Recover the mount configuration before archiving this journal")

const noArchive = "No interrupted partition or file system journal is available to archive"

type archiveReview struct {
	target, journal, config, fingerprint string
	details                              []string
}

func ArchivePlan(ctx context.Context, params map[string]any) (json.RawMessage, error) {
	domain, err := storagebase.DomainLock(ctx)
	if err != nil {
		return nil, err
	}
	defer domain.Close()
	plan, err := loadArchiveReviewLocked(ctx, params)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"target": plan.target, "details": plan.details, "confirmation": plan.target, "fingerprint": plan.fingerprint})
}

func ArchiveExecute(ctx context.Context, params map[string]any, expected string) (json.RawMessage, error) {
	domain, err := storagebase.DomainLock(ctx)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer domain.Close()
	config, err := storagebase.FstabLock(ctx)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer config.Close()
	plan, err := loadArchiveReviewLocked(ctx, params)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if expected == "" || expected != plan.fingerprint {
		return nil, systemops.BeforeMutation(reject("State has changed. Review a new operation plan."))
	}
	if err := ctx.Err(); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if err = defaultService().archiveOriginal(plan); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"message": "Interrupted operation journal archived", "target": plan.target})
}

func (s *service) archiveOriginal(plan *archiveReview) error {
	state, digest, err := s.loadWithDigest(plan.target)
	if err != nil {
		return err
	}
	config, err := s.config()
	if err != nil {
		return err
	}
	if state == nil || state.Phase != "pending" || digest != plan.journal || storagebase.Hash(config) != plan.config {
		return reject("State has changed. Review a new operation plan.")
	}
	root := s.root
	// Keep the actual inode, including unknown fields, exact bytes and ownership.
	// RENAME_NOREPLACE also keeps previous evidence on a retry or name collision.
	dir, err := os.Open(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return err
	}
	name := journalKey(plan.target)
	if err = unix.Renameat2(int(dir.Fd()), name+".json", int(dir.Fd()), name+".history-ack-"+plan.journal+"-"+hex.EncodeToString(salt), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return dir.Sync()
}

func loadArchiveReviewLocked(ctx context.Context, params map[string]any) (*archiveReview, error) {
	input, _ := params["target"].(string)
	target, err := storagebase.RecoveryTarget(input)
	if err != nil {
		return nil, err
	}
	s := defaultService()
	state, digest, err := s.loadWithDigest(target)
	if err != nil {
		return nil, err
	}
	if state == nil || state.Phase != "pending" {
		return nil, reject(noArchive)
	}
	if decoded, e := hex.DecodeString(state.FstabBefore); e != nil || len(decoded) != 32 {
		return nil, reject("Storage recovery record is invalid")
	}
	seen := map[string]bool{}
	for _, d := range state.Identity.Devices {
		if !strings.HasPrefix(d.Path, "/dev/") || filepath.Clean(d.Path) != d.Path || d.DeviceNumber == "" || d.DiskSequence == "" || seen[d.Path] {
			return nil, reject("Storage recovery identity is unavailable")
		}
		seen[d.Path] = true
	}
	if !seen[target] {
		return nil, reject("Storage recovery identity is unavailable")
	}
	config, err := s.config()
	if err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	inventory, err := s.preflight(ctx)
	if err != nil {
		return nil, err
	}
	plan, err := s.archiveReview(state, digest, config, strings.TrimSpace(string(boot)), inventory)
	if err != nil {
		return nil, err
	}
	// Prefer ordinary configuration recovery whenever the saved intent is still usable.
	if state.FstabBefore != storagebase.Hash(state.FstabDesired) {
		if _, err := storagebase.ConfigRecoveryPlanLocked(ctx, map[string]any{"target": target}); err == nil {
			return nil, useConfigurationRecovery
		} else {
			if !storagebase.IsConfigRecoveryConflict(err) {
				return nil, err
			}
		}
	}
	return plan, nil
}

func (s *service) archiveReview(state *transaction, digest, current, boot string, p *storagequery.Preflight) (*archiveReview, error) {
	if boot == "" {
		return nil, reject("Storage recovery identity is unavailable")
	}
	observed := map[string]any{}
	hardwareChanged := false
	for _, d := range state.Identity.Devices {
		if p.Inventory.Rows[d.Path] == nil {
			observed[d.Path] = nil
			hardwareChanged = true
			continue
		}
		id, err := s.identity(p, d.Path)
		if err != nil {
			return nil, err
		}
		if id.BootID != boot {
			return nil, reject("Storage recovery identity changed")
		}
		same := false
		for _, live := range id.Devices {
			if live.Path == d.Path && live.DeviceNumber == d.DeviceNumber && live.DiskSequence == d.DiskSequence && live.WWN == d.WWN && live.Serial == d.Serial {
				same = true
				break
			}
		}
		hardwareChanged = hardwareChanged || !same
		rows := map[string]any{}
		for _, child := range p.Inventory.Descendants(d.Path) {
			rows[child] = p.Inventory.Rows[child]
		}
		observed[d.Path] = map[string]any{"identity": id, "devices": rows}
	}
	configHash := storagebase.Hash(current)
	configIntent := state.FstabBefore != storagebase.Hash(state.FstabDesired)
	canCheckConfig := configIntent && !state.ConfigReconciled
	staleAcknowledgement := configIntent && state.ConfigReconciled && !state.Acknowledged(current, state.FstabBefore, state.FstabDesired)
	if !canCheckConfig && !staleAcknowledgement && !hardwareChanged && state.Identity.BootID == boot {
		return nil, reject(interruptedInspection)
	}
	details := []string{"Interrupted operation: " + state.Action}
	if p.Inventory.Rows[state.Target] == nil {
		details = append(details, "The recorded device is absent")
	} else {
		details = append(details, "The recorded device path is present")
		row := p.Inventory.Rows[state.Target]
		for _, field := range []struct{ key, label string }{{"type", "Current device type: "}, {"fstype", "Current file system: "}, {"uuid", "Current file system UUID: "}} {
			if value := text(row, field.key); value != "" {
				details = append(details, field.label+value)
			}
		}
		for _, point := range mounted(row) {
			details = append(details, "Current mount point: "+point)
		}
	}
	if state.Identity.BootID != boot {
		details = append(details, "The system has restarted since this operation")
	}
	if configHash != state.FstabBefore && current != state.FstabDesired {
		details = append(details, "The mount configuration has changed since this operation")
	}
	for _, step := range state.Steps {
		if step.Completed {
			details = append(details, "Recorded completed step: "+step.Name)
		} else {
			details = append(details, "Recorded unconfirmed step: "+step.Name)
		}
	}
	details = append(details, archiveWarning)
	raw, err := json.Marshal(map[string]any{"journal": digest, "fstab": configHash, "boot": boot, "devices": observed})
	if err != nil {
		return nil, err
	}
	fingerprint, err := systemops.Fingerprint(archiveAction, map[string]any{"target": state.Target}, storagebase.Hash(string(raw)))
	if err != nil {
		return nil, err
	}
	return &archiveReview{target: state.Target, journal: digest, config: configHash, fingerprint: fingerprint, details: details}, nil
}

func SuggestedRecovery(ctx context.Context, target, fallback string) string {
	domain, err := storagebase.TryDomainLock(ctx)
	if err != nil {
		return fallback
	}
	defer domain.Close()
	_, err = loadArchiveReviewLocked(ctx, map[string]any{"target": target})
	if err == nil {
		return archiveAction
	}
	if err == useConfigurationRecovery {
		return "storage.recover"
	}
	return fallback
}
