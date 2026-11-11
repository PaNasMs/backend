package partitionfs

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
)

const mib = uint64(1048576)

func IsAction(action string) bool {
	switch action {
	case "partition.create", "partition.delete", "partition.resize", "filesystem.format", "filesystem.remove", "filesystem.resize":
		return true
	}
	return false
}

type prepared struct {
	previous            *transaction
	target, parent      string
	row                 map[string]any
	table               map[string]any
	identity            storagequery.StorageIdentity
	paths               []string
	config, fingerprint string
	raw                 json.RawMessage
	start, end, size    uint64
}

func defaultService() *service {
	return &service{preflight: storagequery.LoadPreflight, revalidate: revalidate, writeConfig: storagebase.WriteFstab, root: "/var/lib/panasms-agent/storage", owner: 0, write: systemops.AtomicWrite, sys: "/sys/class/block", run: systemops.Command, identity: func(p *storagequery.Preflight, target string) (storagequery.StorageIdentity, error) {
		return p.Identity(target)
	}, config: storagebase.ReadFstab, find: exec.LookPath}
}
func Plan(ctx context.Context, action string, params map[string]any) (json.RawMessage, error) {
	domain, err := storagebase.DomainLock(ctx)
	if err != nil {
		return nil, err
	}
	defer domain.Close()
	p, err := storagequery.LoadPreflight(ctx)
	if err != nil {
		return nil, err
	}
	s := defaultService()
	result, err := s.prepare(ctx, action, params, p)
	if err != nil {
		return nil, err
	}
	if err = storagebase.CheckPendingRoots("partitionfs", result.target, result.identity); err != nil {
		return nil, err
	}
	return result.raw, nil
}
// FAT32 needs 65,525 data clusters, two FATs and 32 reserved sectors.
// Near the minimum mkfs.fat uses one sector per cluster. Round up to a whole MiB.
func fat32MinimumMiB(sector uint64) uint64 {
	const clusters = 65525
	fatSectors := ((clusters+2)*4 + sector - 1) / sector
	return ((32+2*fatSectors+clusters)*sector + mib - 1) / mib
}

func mounted(row map[string]any) []string {
	result := []string{}
	values, _ := row["mountpoints"].([]any)
	for _, value := range values {
		if s, ok := value.(string); ok && s != "" {
			result = append(result, s)
		}
	}
	return result
}
func oneParent(target string, p *storagequery.Preflight) (string, error) {
	parents := p.Inventory.Parents[target]
	if len(parents) != 1 {
		return "", reject("Partition metadata is inconsistent. No changes were made.")
	}
	for path := range parents {
		return path, nil
	}
	return "", reject("Partition metadata is inconsistent. No changes were made.")
}
func (s *service) prepare(ctx context.Context, action string, params map[string]any, p *storagequery.Preflight) (*prepared, error) {
	if !IsAction(action) {
		return nil, reject("Unknown storage operation")
	}
	original := text(params, "target")
	if !strings.HasPrefix(original, "/dev/") {
		return nil, reject("Select a block device")
	}
	target, err := filepath.EvalSymlinks(original)
	if err != nil {
		return nil, reject("The device no longer exists")
	}
	return s.prepareTarget(ctx, action, params, p, target)
}
func (s *service) prepareTarget(ctx context.Context, action string, params map[string]any, p *storagequery.Preflight, target string) (*prepared, error) {
	if !IsAction(action) {
		return nil, reject("Unknown storage operation")
	}
	row := p.Inventory.Rows[target]
	if row == nil {
		return nil, reject("The device no longer exists")
	}
	if err := p.Protected(target, action == "partition.create"); err != nil {
		return nil, err
	}
	cap, err := number(row["size"])
	if err != nil {
		return nil, err
	}
	previous, err := s.load(target)
	if err != nil {
		return nil, err
	}
	out := &prepared{previous: previous, target: target, row: row, paths: []string{target}}
	fs := text(row, "fstype")
	details := []string{}
	switch action {
	case "partition.create":
		kind := text(row, "type")
		if kind != "disk" && kind != "loop" && kind != "md" && !strings.HasPrefix(kind, "raid") {
			return nil, reject("Select a disk or array")
		}
		out.parent = target
		out.table, err = s.checkedLayout(ctx, target, p)
		if err != nil {
			return nil, err
		}
		out.start, err = integer(params, "startMiB", 1, cap/mib)
		if err != nil {
			return nil, err
		}
		out.end, err = integer(params, "endMiB", out.start+1, cap/mib)
		if err != nil {
			return nil, err
		}
		if err = s.noOverlap(p, target, "", out.start*mib, out.end*mib, previous); err != nil {
			return nil, err
		}
		details = []string{target, fmt.Sprintf("New partition: %d–%d MiB", out.start, out.end)}
		if out.table == nil {
			details = append(details, "A new GPT partition table will be created on the empty device.")
		}
	case "partition.delete", "partition.resize":
		if text(row, "type") != "part" {
			return nil, reject("Select a partition")
		}
		if err = p.Unused(target, false); err != nil {
			return nil, err
		}
		out.parent, err = oneParent(target, p)
		if err != nil {
			return nil, err
		}
		out.paths = append(out.paths, out.parent)
		out.table, err = s.checkedLayout(ctx, out.parent, p)
		if err != nil {
			return nil, err
		}
		if out.table == nil {
			return nil, reject("Partition metadata is inconsistent. No changes were made.")
		}
		if n, e := number(row["partn"]); e != nil || n == 0 {
			return nil, reject("Invalid storage geometry")
		}
		if action == "partition.resize" {
			if fs != "" && fs != "ext2" && fs != "ext3" && fs != "ext4" {
				return nil, reject("Resizing a partition with this file system is not supported yet; use separate file system operations")
			}
			parentCap, e := number(p.Inventory.Rows[out.parent]["size"])
			if e != nil {
				return nil, e
			}
			out.size, err = integer(params, "sizeMiB", 16, parentCap/mib)
			if err != nil {
				return nil, err
			}
			out.start, err = s.sectorValue(text(row, "kname"), "start")
			if err != nil {
				return nil, err
			}
			if parentCap < mib || out.size > math.MaxUint64/mib || out.start > math.MaxUint64-out.size*mib || out.start+out.size*mib >= parentCap-mib {
				return nil, reject("Outside disk boundaries")
			}
			if err = s.noOverlap(p, out.parent, target, out.start, out.start+out.size*mib, previous); err != nil {
				return nil, err
			}
			details = []string{target, fmt.Sprintf("New size: %d MiB", out.size), "The ext file system and partition will be resized in a safe order"}
		}
	case "filesystem.remove":
		if err = p.Unused(target, false); err != nil {
			return nil, err
		}
		switch fs {
		case "ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs":
		default:
			return nil, reject("Select a supported data file system, not a RAID member or encrypted container")
		}
		details = []string{target, "Removing the file system makes all its data inaccessible. The RAID array and partition layout are preserved."}
	case "filesystem.format":
		if err = p.Unused(target, false); err != nil {
			return nil, err
		}
		format := text(params, "format")
		command := storagequery.FormatCommand(format)
		if len(command) == 0 {
			return nil, reject("The utility for creating this file system is unavailable")
		}
		if _, err = s.find(command[0]); err != nil {
			return nil, reject("The utility for creating this file system is unavailable")
		}
		if fs == "linux_raid_member" {
			return nil, reject("Cannot format a RAID member")
		}
		if format == "fat32" {
			output, err := s.run(ctx, []string{"blockdev", "--getss", target}, systemops.CommandOptions{})
			if err != nil {
				return nil, err
			}
			sector, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
			if err != nil || sector < 512 || sector > 4096 || sector&(sector-1) != 0 {
				return nil, reject("Invalid storage geometry")
			}
			minimum := fat32MinimumMiB(sector)
			if cap/mib < minimum {
				return nil, reject(fmt.Sprintf("FAT32 requires at least %d MiB on this device. Choose FAT (auto) for a smaller volume.", minimum))
			}
		}
		details = []string{target, "New file system: " + format}
		if fs != "" {
			details = append(details, "Current file system: "+fs)
		}
		details = append(details, "FORMATTING WILL DESTROY DATA")
	case "filesystem.resize":
		switch fs {
		case "ext2", "ext3", "ext4", "btrfs", "xfs":
		default:
			return nil, reject("Resizing is not supported")
		}
		if strings.HasPrefix(fs, "ext") {
			if err = p.Unused(target, false); err != nil {
				return nil, err
			}
			out.size, err = integer(params, "sizeMiB", 16, cap/mib)
			if err != nil {
				return nil, err
			}
		} else {
			points := mounted(row)
			if len(points) == 0 {
				return nil, reject("The file system must be mounted")
			}
			if params["sizeMiB"] != nil {
				out.size, err = integer(params, "sizeMiB", 0, cap/mib)
				if err != nil {
					return nil, err
				}
			}
			if fs == "xfs" && out.size != 0 {
				return nil, reject("XFS can only grow to the device size")
			}
			if fs == "btrfs" {
				output, e := s.run(ctx, []string{"btrfs", "filesystem", "show", "--raw", points[0]}, systemops.CommandOptions{})
				if e != nil {
					return nil, e
				}
				if !regexp.MustCompile(`Total devices\s+1\b`).Match(output) {
					return nil, reject("Resizing multi-device Btrfs requires a separate workflow")
				}
			}
		}
		if out.size == 0 {
			details = []string{target, fmt.Sprintf("File system %s will use the whole device: %d MiB", fs, cap/mib)}
		} else {
			details = []string{target, fmt.Sprintf("New file system size: %d of %d MiB", out.size, cap/mib)}
		}
	}
	if len(details) == 0 {
		details = []string{target}
	}
	for i, value := range details {
		if row := p.Inventory.Rows[value]; row != nil && strings.HasPrefix(text(row, "kname"), "dm-") && text(row, "name") != "" {
			details[i] = "/dev/mapper/" + text(row, "name")
		}
	}
	out.identity, err = s.identity(p, target)
	if err != nil {
		return nil, err
	}
	out.config, err = s.config()
	if err != nil {
		return nil, err
	}
	state := map[string]any{}
	for _, path := range out.paths {
		for _, child := range p.Inventory.Descendants(path) {
			state[child] = p.Inventory.Rows[child]
		}
	}
	sort.Strings(out.paths)
	data, err := json.Marshal(map[string]any{"devices": state, "identity": out.identity, "table": out.table, "fstab": out.config, "previous": previous})
	if err != nil {
		return nil, err
	}
	var normalized any
	if err = systemops.Decode(data, &normalized); err != nil {
		return nil, err
	}
	out.fingerprint, err = systemops.Fingerprint(action, params, normalized)
	if err != nil {
		return nil, err
	}
	if previous != nil && previous.Phase == "pending" {
		details = append(details, "Interrupted operation: "+previous.Action, interruptedInspection)
	}
	out.raw, err = json.Marshal(map[string]any{"target": target, "details": details, "confirmation": target, "fingerprint": out.fingerprint})
	return out, err
}
func (s *service) noOverlap(p *storagequery.Preflight, parent, except string, start, end uint64, previous *transaction) error {
	for child, parents := range p.Inventory.Parents {
		if child == except || !parents[parent] || text(p.Inventory.Rows[child], "type") != "part" {
			continue
		}
		row := p.Inventory.Rows[child]
		a, err := s.sectorValue(text(row, "kname"), "start")
		if err != nil {
			return err
		}
		size, err := number(row["size"])
		if err != nil {
			return err
		}
		if a > math.MaxUint64-size || !(end <= a || start >= a+size) {
			if previous != nil && previous.Phase == "pending" {
				return reject("The partition overlaps an existing partition. Review the recovery report for the interrupted operation.")
			}
			return reject("The partition overlaps an existing partition")
		}
	}
	return nil
}
