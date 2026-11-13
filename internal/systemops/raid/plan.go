package raid

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
)

type prepared struct {
	Target, Extra, Old, Level, Fstab, Config string
	State                                    *arrayState
	Paths                                    []string
	Identities                               map[string]storagequery.StorageIdentity
	Delete                                   *deletion
	Record                                   *reshapeRecord
	NewCount                                 int
	details                                  []string
	fingerprint                              string
}

func Plan(ctx context.Context, action string, params map[string]any) (json.RawMessage, error) {
	lock, err := storagebase.DomainLock(ctx)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	p, err := defaultService().prepare(ctx, action, params)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"target": p.Target, "confirmation": p.Target, "details": p.details, "fingerprint": p.fingerprint})
}

func (s *service) device(pf *storagequery.Preflight, input string) (string, error) {
	if !strings.HasPrefix(input, "/dev/") || filepath.Clean(input) != input {
		return "", reject("Select a block device")
	}
	path, err := s.resolve(input)
	if err != nil || pf.Inventory.Rows[path] == nil || filepath.Dir(path) != "/dev" {
		return "", reject("The device no longer exists")
	}
	return path, pf.Protected(path, false)
}

func (s *service) empty(pf *storagequery.Preflight, input string) (string, error) {
	path, err := s.device(pf, input)
	if err != nil {
		return "", err
	}
	row := pf.Inventory.Rows[path]
	if !slices.Contains([]string{"disk", "part", "loop"}, text(row, "type")) || text(row, "fstype") != "" {
		return "", reject("Select an unused disk or partition without file system or RAID metadata")
	}
	if err = pf.Unused(path, false); err != nil {
		return "", err
	}
	return path, nil
}

func (s *service) prepare(ctx context.Context, action string, params map[string]any) (*prepared, error) {
	pf, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	p := &prepared{Level: text(params, "level"), Identities: map[string]storagequery.StorageIdentity{}}
	if action == "raid.create" {
		name := text(params, "name")
		min := map[string]int{"0": 2, "1": 2, "5": 3, "6": 4, "10": 4}[p.Level]
		if !arrayName.MatchString(name) || min == 0 {
			return nil, reject("Select a valid RAID name and level")
		}
		items, ok := params["members"].([]any)
		if !ok || len(items) < min || len(items) > 4096 || p.Level == "10" && len(items)%2 != 0 {
			return nil, reject("Invalid member count for this RAID level")
		}
		if _, err = os.Lstat(filepath.Join("/dev/md", name)); !os.IsNotExist(err) {
			return nil, reject("Array name is already in use")
		}
		p.Target = name
		for _, item := range items {
			value, _ := item.(string)
			path, err := s.empty(pf, value)
			if err != nil {
				return nil, err
			}
			if slices.Contains(p.Paths, path) {
				return nil, reject("Duplicate members")
			}
			p.Paths = append(p.Paths, path)
		}
		p.details = append([]string{"Create RAID" + p.Level}, p.Paths...)
		if p.Level == "0" {
			p.details = append(p.details, "RAID0 has no redundancy: a disk failure causes array data loss")
		} else {
			p.details = append(p.details, "Array synchronization will continue in the background")
		}
	} else {
		p.Target, err = s.device(pf, text(params, "target"))
		if err != nil {
			return nil, err
		}
		p.State, err = s.readArray(filepath.Base(p.Target))
		if err != nil {
			return nil, err
		}
		p.Paths = []string{p.Target}
		p.details = []string{p.Target}
		for _, m := range p.State.Members {
			p.Paths = append(p.Paths, m.Path)
			p.details = append(p.details, m.Path)
		}
		if err = s.actionPlan(ctx, action, params, p, pf); err != nil {
			return nil, err
		}
	}
	p.Fstab, err = s.readFstab()
	if err != nil {
		return nil, err
	}
	if action == "raid.create" || action == "raid.delete" {
		conf, err := os.ReadFile(s.config)
		if err != nil {
			return nil, err
		}
		p.Config = string(conf)
	}
	for _, path := range p.Paths {
		if _, ok := p.Identities[path]; ok {
			continue
		}
		id, err := s.identity(pf, path)
		if err != nil {
			return nil, err
		}
		if err = storagebase.CheckPendingRoots("raid", path, id); err != nil {
			return nil, err
		}
		p.Identities[path] = id
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	p.fingerprint, err = systemops.Fingerprint(action, params, string(raw))
	return p, err
}

func (s *service) actionPlan(ctx context.Context, action string, params map[string]any, p *prepared, pf *storagequery.Preflight) error {
	a := p.State
	switch action {
	case "raid.check", "raid.check-stop":
		if a.Level == "raid0" || a.Reshaping {
			return reject("Wait for reshape to finish on a redundant array")
		}
		if action == "raid.check" && a.Sync != "idle" || action == "raid.check-stop" && a.Sync != "check" {
			return reject("The requested redundancy check does not match current array maintenance")
		}
	case "raid.pause", "raid.resume":
		if !a.Reshaping || a.Metadata != "1.2" || (a.Level != "raid5" && a.Level != "raid6") {
			return reject("No supported unfinished array reshape")
		}
		if action == "raid.pause" {
			if a.Sync != "reshape" {
				return reject("Reshape is not running")
			}
			return nil
		}
		if a.Sync != "idle" && a.Sync != "frozen" || slices.Contains([]string{"clear", "inactive", "suspended"}, a.Array) {
			return reject("The array is not ready to resume reshape")
		}
		rec, err := s.record(a.UUID)
		if err != nil {
			return err
		}
		p.Record = rec
		if !safeResume(a, rec) {
			return reject("Recover missing or failed array members first")
		}
	case "raid.add", "raid.grow", "raid.replace", "raid.convert":
		if !slices.Contains([]string{"raid1", "raid5", "raid6", "raid10"}, a.Level) || a.Sync != "idle" || a.Reshaping {
			return reject("Wait for the current array operation to finish")
		}
		if action == "raid.convert" {
			if !synchronized(a) || a.Metadata != "1.2" {
				return reject("Conversion requires synchronized MD 1.2 members without spares")
			}
			switch {
			case a.Level == "raid1" && p.Level == "5" && a.Count == 2, a.Level == "raid5" && p.Level == "6":
				p.NewCount = a.Count + 1
			case a.Level == "raid6" && p.Level == "5":
				p.NewCount = a.Count - 1
			default:
				return reject("Supported conversions: two-disk RAID1 to RAID5, RAID5 to RAID6, RAID6 to RAID5")
			}
			if err := s.conversionBackup(ctx, p); err != nil {
				return err
			}
			p.details = append(p.details, fmt.Sprintf("%s → RAID%s; members: %d → %d", strings.ToUpper(a.Level), p.Level, a.Count, p.NewCount), "File systems are not resized. Recovery data will remain on the system disk.")
			if p.NewCount < a.Count {
				if text(params, "replacement") != "" {
					return reject("This conversion does not need an additional disk")
				}
				p.details = append(p.details, "Redundancy decreases to one failed member. One member becomes a spare.")
				return nil
			}
		}
		extra, err := s.empty(pf, text(params, "replacement"))
		if err != nil {
			return err
		}
		size, err := uintValue(pf.Inventory.Rows[extra]["size"])
		if err != nil {
			return err
		}
		minimum := ^uint64(0)
		for _, m := range a.Members {
			n, err := uintValue(pf.Inventory.Rows[m.Path]["size"])
			if err != nil {
				return err
			}
			minimum = min(minimum, n)
		}
		if size < minimum {
			return reject("The new disk is smaller than the array members")
		}
		p.Extra = extra
		p.Paths = append(p.Paths, extra)
		p.details = append(p.details, "New member: "+extra)
		if action == "raid.replace" {
			old, err := s.device(pf, text(params, "member"))
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(a.Members, func(m member) bool { return m.Path == old }) {
				return reject("Old member not found")
			}
			p.Old = old
		}
		if action == "raid.grow" {
			if (a.Level != "raid5" && a.Level != "raid6") || a.Metadata != "1.2" || !synchronized(a) {
				return reject("Expansion requires synchronized RAID5 or RAID6 members with MD 1.2 metadata and no spares")
			}
			parity := 1
			if a.Level == "raid6" {
				parity = 2
			}
			p.NewCount = a.Count + 1
			p.details = append(p.details, fmt.Sprintf("Members: %d → %d", a.Count, p.NewCount), fmt.Sprintf("Array capacity: approximately %d → %d MiB", a.ComponentKiB*uint64(a.Count-parity)/1024, a.ComponentKiB*uint64(p.NewCount-parity)/1024), "Partitions and file systems keep their current sizes.")
		}
	case "raid.delete":
		if a.Sync != "idle" || a.Reshaping {
			return reject("Wait for the array operation to finish")
		}
		remove, ok := params["removeShares"].(bool)
		if _, exists := params["removeShares"]; exists && !ok {
			return reject("Choose whether to stop sharing folders on this array")
		}
		d, err := s.deletionPlan(ctx, p, pf, remove)
		if err != nil {
			return err
		}
		p.Delete = d
		p.details = append(p.details, "ARRAY DATA WILL BECOME INACCESSIBLE", "Volumes will be unmounted and member RAID metadata removed")
		for _, share := range d.Remove {
			p.details = append(p.details, "Sharing will be removed: "+share.Name+" ("+share.Path+")")
		}
	default:
		return reject("Unknown RAID operation")
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
