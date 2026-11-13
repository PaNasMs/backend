package raid

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"panasms.local/backend/internal/systemops/accounts"
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/localmounts"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
)

type deletion struct {
	Mounts         []folders.LiveMount
	Shares, Remove []accounts.StorageShare
	UUIDs          map[string]bool
}

func (s *service) deletionPlan(ctx context.Context, p *prepared, pf *storagequery.Preflight, remove bool) (*deletion, error) {
	d := &deletion{UUIDs: map[string]bool{}}
	all, err := s.mounts()
	if err != nil {
		return nil, err
	}
	children := pf.Inventory.Descendants(p.Target)
	for _, path := range children {
		row := pf.Inventory.Rows[path]
		if path != p.Target && text(row, "type") != "part" {
			return nil, reject("Detach dependent devices before removing the array")
		}
		holders, err := pf.Holders(text(row, "kname"))
		if err != nil {
			return nil, err
		}
		if len(holders) > 0 {
			return nil, reject("Detach dependent devices before removing the array")
		}
		id, err := s.identity(pf, path)
		if err != nil {
			return nil, err
		}
		p.Paths = append(p.Paths, path)
		uuid := text(row, "uuid")
		if uuid != "" {
			for other, otherRow := range pf.Inventory.Rows {
				if !slices.Contains(children, other) && strings.EqualFold(text(otherRow, "uuid"), uuid) {
					return nil, reject("Ambiguous volume UUID")
				}
			}
			d.UUIDs[uuid] = true
		}
		points, _ := row["mountpoints"].([]any)
		for _, m := range all {
			matched := slices.ContainsFunc(id.Devices, func(dev storagequery.DeviceIdentity) bool { return dev.Path == path && dev.DeviceNumber == m.Device })
			if !matched && m.FSType == "btrfs" && text(row, "fstype") == "btrfs" && slices.Contains(points, any(m.Target)) {
				dir, err := folders.OpenDirectory(m.Target)
				if err != nil {
					return nil, err
				}
				err = storagebase.VerifyBtrfsMount(dir, path, uuid)
				dir.Close()
				if err != nil {
					return nil, err
				}
				matched = true
			}
			if matched {
				if err := folders.MountPath(m.Target); err != nil {
					return nil, err
				}
				d.Mounts = append(d.Mounts, m)
			}
		}
	}
	sort.Slice(d.Mounts, func(i, j int) bool {
		a, b := d.Mounts[i].Target, d.Mounts[j].Target
		if len(a) != len(b) {
			return len(a) > len(b)
		}
		return a < b
	})
	if len(d.Mounts) > 0 {
		d.Shares, err = s.shares()
		if err != nil {
			return nil, err
		}
		var keep []accounts.StorageShare
		ignore := map[string]bool{}
		closing := map[string]bool{}
		for _, share := range d.Shares {
			if remove && slices.ContainsFunc(d.Mounts, func(m folders.LiveMount) bool { return within(share.Path, m.Target) }) {
				d.Remove = append(d.Remove, share)
				if share.NFS {
					ignore[share.Path] = true
				}
				if share.SMB {
					for _, m := range d.Mounts {
						if within(share.Path, m.Target) {
							closing[m.Target] = true
						}
					}
				}
			} else {
				keep = append(keep, share)
			}
		}
		if len(d.Remove) > 0 {
			if err = accounts.CheckStorageShareRemoval(); err != nil {
				return nil, err
			}
		}
		if err = localmounts.CheckStorageBlockers(ctx, d.Mounts, all, keep, ignore, closing); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func withoutArray(config, uuid string) string {
	rows := strings.Split(config, "\n")
	return strings.Join(slices.DeleteFunc(rows, func(row string) bool {
		words := strings.Fields(row)
		if len(words) < 2 || words[0] != "ARRAY" {
			return false
		}
		for _, word := range words[1:] {
			if strings.HasPrefix(word, "#") {
				break
			}
			if value, ok := strings.CutPrefix(word, "UUID="); ok && compactUUID(value) == compactUUID(uuid) {
				return true
			}
		}
		return false
	}), "\n")
}

func (s *service) retireRecord(uuid string) error {
	rec, err := s.record(uuid)
	if err != nil || rec == nil {
		return err
	}
	path := recordPath(rec.Backup)
	if err = os.Rename(path, strings.TrimSuffix(path, ".json")+".retired"); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
