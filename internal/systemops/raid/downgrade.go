package raid

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/disksleep"
	"panasms.local/backend/internal/systemops/storagebase"
)

func (s *service) offsets(target string, a *arrayState) (uint64, error) {
	var offset uint64
	for _, m := range a.Members {
		raw, err := os.ReadFile(filepath.Join(s.sys, filepath.Base(target), "md", "dev-"+filepath.Base(m.Path), "offset"))
		if err != nil {
			return 0, err
		}
		n, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil || n == 0 || (offset != 0 && n != offset) {
			return 0, reject("RAID member data offsets must agree")
		}
		offset = n
	}
	return offset, nil
}

func (s *service) downgradeOffset(target string, a *arrayState) (uint64, error) {
	offset, err := s.offsets(target, a)
	if err != nil {
		return 0, err
	}
	// Keep at least 1 MiB for MD metadata. A small overlapping offset window
	// can lose stripes when mdadm restarts an interrupted layout conversion.
	const sectorMiB = 2048
	if offset >= 65*sectorMiB && a.Chunk <= 512<<10 {
		return offset - 64*sectorMiB, nil
	}
	if offset >= 8*sectorMiB && a.Chunk <= 512<<10 {
		return sectorMiB, nil
	}
	// Keep the external backup and offline export path for smaller offsets.
	return 0, nil
}

func (s *service) memberUUIDs(ctx context.Context, a *arrayState) ([]string, error) {
	ids := make([]string, a.Count)
	for _, m := range a.Members {
		slot, err := strconv.Atoi(m.Slot)
		if err != nil || slot < 0 || slot >= len(ids) || ids[slot] != "" {
			return nil, reject("Invalid RAID member slot")
		}
		raw, err := s.run(ctx, []string{"mdadm", "--examine", "--export", m.Path}, systemops.CommandOptions{})
		if err != nil {
			return nil, err
		}
		var arrayID, deviceID string
		for _, field := range strings.Fields(string(raw)) {
			if id, ok := strings.CutPrefix(field, "MD_UUID="); ok {
				arrayID = compactUUID(id)
			}
			if id, ok := strings.CutPrefix(field, "MD_DEV_UUID="); ok && uuidPattern.MatchString(id) {
				deviceID = compactUUID(id)
			}
		}
		if arrayID != compactUUID(a.UUID) || deviceID == "" || slices.Contains(ids, deviceID) {
			return nil, reject("RAID member identity changed")
		}
		ids[slot] = deviceID
	}
	return ids, nil
}

func (s *service) finishDowngrade(ctx context.Context, target string, a *arrayState, rec *reshapeRecord) error {
	if a.Reshaping || a.Sync != "idle" || a.Degraded != 0 {
		return reject("Wait for the current RAID operation to finish")
	}
	if a.Level == "raid5" && a.Count == rec.Members {
		return s.retireRecord(rec.UUID)
	}
	if a.Level != "raid6" || a.Count != rec.SourceCount || !synchronized(a) {
		return reject("Inspect the pending RAID downgrade and member geometry")
	}
	offset, err := s.offsets(target, a)
	if err != nil {
		return err
	}
	slots, err := s.memberUUIDs(ctx, a)
	if err != nil {
		return err
	}
	if !slices.Equal(slots, rec.SourceSlots) {
		return reject("RAID member slots changed after approval")
	}
	if a.Layout == "2" && offset == rec.SourceOffset {
		return s.retireRecord(rec.UUID)
	}
	if a.Layout != "18" || offset != rec.LayoutOffset {
		return reject("RAID layout change has not reached its recorded offset")
	}
	_, err = s.run(ctx, scoped("convert", "--grow", target, "--level=5", "--raid-devices="+strconv.Itoa(rec.Members)), systemops.CommandOptions{Operation: true})
	if err != nil {
		return err
	}
	final, err := s.readArray(filepath.Base(target))
	if err != nil {
		return err
	}
	if compactUUID(final.UUID) != compactUUID(rec.UUID) || final.Level != "raid5" || final.Count != rec.Members || final.Reshaping || final.Degraded != 0 {
		return reject("Inspect the final RAID5 membership")
	}
	return s.retireRecord(rec.UUID)
}

// A timer completes only an already-approved layout change. It never assembles
// an absent array or resumes a paused reshape.
func AdvanceDowngrades(ctx context.Context) error {
	lock, err := storagebase.DomainLock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	return disksleep.WithStorageLock(func() error {
		s := defaultService()
		if err := storagebase.SecureDirectory(s.reshapeRoot, s.owner, false); os.IsNotExist(err) {
			return nil
		} else if err != nil {
			return err
		}
		entries, err := os.ReadDir(s.reshapeRoot)
		if err != nil {
			return err
		}
		var failures []error
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".json") {
				continue
			}
			id := strings.TrimSuffix(name, ".json")
			if !uuidPattern.MatchString(id) {
				id = strings.ReplaceAll(id, "-", ":")
			}
			rec, err := s.record(id)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if rec == nil || rec.LayoutOffset == 0 {
				continue
			}
			target, err := s.activeTarget(id)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if target == "" {
				continue
			}
			a, err := s.readArray(filepath.Base(target))
			if err == nil && compactUUID(a.UUID) == compactUUID(id) && !a.Reshaping && a.Sync == "idle" {
				err = s.finishDowngrade(ctx, target, a, rec)
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", id, err))
			}
		}
		return errors.Join(failures...)
	})
}
