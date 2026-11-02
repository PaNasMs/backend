package storagequery

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"panasms.local/backend/internal/system"
)

type service struct {
	sys, fstab string
	inventory  func(context.Context) ([]map[string]any, error)
	resolve    func(string) (string, error)
}

func defaultService() *service {
	return &service{
		sys: "/sys/class/block", fstab: "/etc/fstab", resolve: filepath.EvalSymlinks,
		inventory: func(ctx context.Context) ([]map[string]any, error) {
			return system.BlockDevicesRead(ctx, "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,FSTYPE,UUID,LABEL,PARTUUID,PARTTYPE,MOUNTPOINTS,PKNAME,RO,PARTN,ROTA,TRAN,MAJ:MIN")
		},
	}
}

func (s *service) dependencies(name, kind string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.sys, name, kind))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func (s *service) preflight(ctx context.Context) (*Preflight, error) {
	rows, err := s.inventory(ctx)
	if err != nil {
		return nil, err
	}
	inv, err := NewInventory(rows, s.resolve)
	if err != nil {
		return nil, rejectf("Could not verify storage dependencies. No changes were made.")
	}
	for _, row := range inv.Rows {
		if err := validateObservation(row); err != nil {
			return nil, err
		}
	}
	fstab, err := os.ReadFile(s.fstab)
	if err != nil {
		return nil, rejectf("Could not verify storage dependencies. No changes were made.")
	}
	sources := SystemSources(string(fstab))
	for source := range sources {
		if strings.HasPrefix(source, "/dev/") {
			resolved, err := s.resolve(source)
			if err != nil {
				return nil, rejectf("Could not verify storage dependencies. No changes were made.")
			}
			sources[resolved] = true
		}
	}
	system, carriers, err := inv.Protection(sources, func(name string) ([]string, error) { return s.dependencies(name, "slaves") })
	if err != nil {
		return nil, rejectf("Could not verify storage dependencies. No changes were made.")
	}
	return &Preflight{inv, system, carriers, func(name string) ([]string, error) { return s.dependencies(name, "holders") }}, nil
}

func (s *service) raidCandidates(ctx context.Context, target string) (any, error) {
	p, err := s.preflight(ctx)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(target, "/dev/") {
		return nil, rejectf("Select a block device")
	}
	target, err = s.resolve(target)
	if err != nil || p.Inventory.Rows[target] == nil {
		return nil, rejectf("The device no longer exists")
	}
	row := p.Inventory.Rows[target]
	name := row["kname"].(string)
	md, err := os.Stat(filepath.Join(s.sys, name, "md"))
	if err != nil || !md.IsDir() {
		return nil, rejectf("Array no longer available. Refresh the device list.")
	}
	members, err := s.dependencies(name, "slaves")
	if err != nil || len(members) == 0 {
		return nil, rejectf("Could not determine array member sizes")
	}
	var minimum uint64
	for index, member := range members {
		size, ok := deviceSize(p.Inventory.Rows["/dev/"+member]["size"])
		if !ok || size <= 0 {
			return nil, rejectf("Could not determine array member sizes")
		}
		if index == 0 || size < minimum {
			minimum = size
		}
	}
	candidates := []map[string]any{}
	for _, path := range p.Inventory.Order {
		row := p.Inventory.Rows[path]
		kind, _ := row["type"].(string)
		size, ok := deviceSize(row["size"])
		fs, _ := row["fstype"].(string)
		if (kind != "disk" && kind != "part") || fs != "" || !ok || size < minimum {
			continue
		}
		if p.Protected(path, false) != nil || p.Unused(path, false) != nil {
			continue
		}
		candidates = append(candidates, publicRow(row))
	}
	return map[string]any{"devices": candidates}, nil
}

func RaidCandidates(ctx context.Context, target string) (any, error) {
	return defaultService().raidCandidates(ctx, target)
}

func validateObservation(row map[string]any) error {
	bad := func() error { return rejectf("Could not verify storage dependencies. No changes were made.") }
	if kind, ok := row["type"].(string); !ok || kind == "" {
		return bad()
	}
	if _, ok := deviceSize(row["size"]); !ok {
		return bad()
	}
	switch value := row["ro"].(type) {
	case bool:
	case json.Number:
		if value != "0" && value != "1" {
			return bad()
		}
	case float64:
		if value != 0 && value != 1 {
			return bad()
		}
	default:
		return bad()
	}
	mounts, ok := row["mountpoints"].([]any)
	if !ok {
		return bad()
	}
	for _, mount := range mounts {
		if mount != nil {
			if _, ok := mount.(string); !ok {
				return bad()
			}
		}
	}
	return nil
}

func Query(ctx context.Context, view, target string) (json.RawMessage, error) {
	var value any
	var err error
	switch view {
	case "storage-options":
		value, err = Options(ctx)
	case "raid-candidates":
		value, err = RaidCandidates(ctx, target)
	default:
		return nil, rejectf("Unknown management view")
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func deviceSize(value any) (uint64, bool) {
	switch n := value.(type) {
	case json.Number:
		size, err := strconv.ParseUint(string(n), 10, 64)
		return size, err == nil
	case float64:
		if n < 0 || n >= 18446744073709551616.0 || math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n {
			return 0, false
		}
		return uint64(n), true
	default:
		return 0, false
	}
}
