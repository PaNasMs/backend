package storagequery

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type DeviceIdentity struct {
	Path, DeviceNumber, DiskSequence, UUID, PartUUID, WWN, Serial string
}

// Identity is an observation, not authorization. Mutation callers must acquire
// their maintenance/domain/device locks, rebuild inventory and preflight, and
// compare identities before writing. Never upgrade a query result into a lease.
func (inv *Inventory) Identity(path, sysRoot string) ([]DeviceIdentity, error) {
	seen := map[string]bool{}
	result := []DeviceIdentity{}
	var visit func(string) error
	visit = func(path string) error {
		if seen[path] {
			return nil
		}
		seen[path] = true
		row := inv.Rows[path]
		if row == nil {
			return fmt.Errorf("The device no longer exists")
		}
		name := row["kname"].(string)
		node := filepath.Join(sysRoot, name)
		disk := node
		if _, err := os.Stat(filepath.Join(node, "partition")); err == nil {
			resolved, err := filepath.EvalSymlinks(node)
			if err != nil {
				return err
			}
			disk = filepath.Dir(resolved)
		} else if !os.IsNotExist(err) {
			return err
		}
		number, sequence := readText(filepath.Join(node, "dev")), readText(filepath.Join(disk, "diskseq"))
		if number == "" || sequence == "" {
			return fmt.Errorf("Could not verify storage identity")
		}
		value := func(key string) string { s, _ := row[key].(string); return s }
		result = append(result, DeviceIdentity{path, number, sequence, value("uuid"), value("partuuid"), value("wwn"), value("serial")})
		for parent := range inv.Parents[path] {
			if err := visit(parent); err != nil {
				return err
			}
		}
		slaves, err := os.ReadDir(filepath.Join(node, "slaves"))
		if err != nil {
			return err
		}
		for _, slave := range slaves {
			if err := visit("/dev/" + slave.Name()); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(path); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}
