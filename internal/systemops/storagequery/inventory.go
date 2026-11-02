package storagequery

import (
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// Inventory retains every parent of a repeated lsblk node (for example a RAID
// device below several members). A presentation row's parent is not identity.
type Inventory struct {
	Rows    map[string]map[string]any
	Order   []string
	Parents map[string]map[string]bool
}

func NewInventory(devices []map[string]any, resolve func(string) (string, error)) (*Inventory, error) {
	inv := &Inventory{Rows: map[string]map[string]any{}, Parents: map[string]map[string]bool{}}
	var visit func(map[string]any, string) error
	visit = func(input map[string]any, parent string) error {
		path, _ := input["path"].(string)
		if !strings.HasPrefix(path, "/dev/") {
			return fmt.Errorf("invalid block device path")
		}
		path, err := resolve(path)
		if err != nil || !strings.HasPrefix(path, "/dev/") || filepath.Clean(path) != path {
			return fmt.Errorf("could not resolve block device")
		}
		name, _ := input["kname"].(string)
		if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
			return fmt.Errorf("invalid kernel device name")
		}
		row := make(map[string]any, len(input))
		for k, v := range input {
			if k != "children" {
				row[k] = v
			}
		}
		row["path"] = path
		if parent == "" {
			row["parent"] = nil
		} else {
			row["parent"] = parent
		}
		if previous, exists := inv.Rows[path]; exists {
			for key, value := range row {
				if key != "parent" && key != "pkname" && !reflect.DeepEqual(previous[key], value) {
					return fmt.Errorf("inconsistent block device identity")
				}
			}
			for key, value := range previous {
				if key != "parent" && key != "pkname" && !reflect.DeepEqual(row[key], value) {
					return fmt.Errorf("inconsistent block device identity")
				}
			}
		} else {
			inv.Order = append(inv.Order, path)
		}
		inv.Rows[path] = row
		if inv.Parents[path] == nil {
			inv.Parents[path] = map[string]bool{}
		}
		if parent != "" {
			inv.Parents[path][parent] = true
		}
		children, exists := input["children"]
		if !exists || children == nil {
			return nil
		}
		values, ok := children.([]any)
		if !ok {
			return fmt.Errorf("invalid block device children")
		}
		for _, value := range values {
			child, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("invalid block device child")
			}
			if err := visit(child, path); err != nil {
				return err
			}
		}
		return nil
	}
	for _, row := range devices {
		if err := visit(row, ""); err != nil {
			return nil, err
		}
	}
	return inv, nil
}

func (inv *Inventory) Descendants(path string) []string {
	seen := map[string]bool{path: true}
	for changed := true; changed; {
		changed = false
		for child, parents := range inv.Parents {
			if seen[child] {
				continue
			}
			for parent := range parents {
				if seen[parent] {
					seen[child] = true
					changed = true
					break
				}
			}
		}
	}
	result := make([]string, 0, len(seen))
	for path := range seen {
		result = append(result, path)
	}
	sort.Strings(result)
	return result
}

func SystemMount(point string) bool {
	if point == "[SWAP]" {
		return true
	}
	for _, root := range []string{"/", "/boot", "/efi", "/usr", "/var", "/home"} {
		if point == root || root != "/" && strings.HasPrefix(point, root+"/") {
			return true
		}
	}
	return false
}

func SystemSources(fstab string) map[string]bool {
	result := map[string]bool{}
	for _, line := range strings.Split(fstab, "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) >= 3 && (fields[2] == "swap" || SystemMount(fields[1])) {
			result[fields[0]] = true
		}
	}
	return result
}

func SystemPartition(row map[string]any, sources map[string]bool) bool {
	if mounts, ok := row["mountpoints"].([]any); ok {
		for _, mount := range mounts {
			if point, ok := mount.(string); ok && SystemMount(point) {
				return true
			}
		}
	}
	kind, _ := row["parttype"].(string)
	switch strings.ToLower(kind) {
	case "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "21686148-6449-6e6f-744e-656564454649", "bc13c2ff-59e6-4262-a352-b275fd6f7172", "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", "0xef", "0x82":
		return true
	}
	if row["fstype"] == "swap" {
		return true
	}
	for field, prefix := range map[string]string{"path": "", "uuid": "UUID=", "partuuid": "PARTUUID=", "label": "LABEL="} {
		if value, ok := row[field].(string); ok && value != "" && sources[prefix+value] {
			return true
		}
	}
	return false
}

// Protection follows both lsblk ancestry and kernel slave relationships. Missing
// dependency evidence is an error, never evidence that a device is safe to use.
func (inv *Inventory) Protection(sources map[string]bool, slaves func(string) ([]string, error)) (map[string]bool, map[string]bool, error) {
	system, carriers := map[string]bool{}, map[string]bool{}
	var backing func(string) error
	backing = func(path string) error {
		if carriers[path] {
			return nil
		}
		carriers[path] = true
		row, ok := inv.Rows[path]
		if !ok {
			return fmt.Errorf("storage dependency disappeared")
		}
		members, err := slaves(row["kname"].(string))
		if err != nil {
			return err
		}
		for _, member := range members {
			if err := backing("/dev/" + member); err != nil {
				return err
			}
		}
		for parent := range inv.Parents[path] {
			if err := backing(parent); err != nil {
				return err
			}
		}
		return nil
	}
	for path, row := range inv.Rows {
		if SystemPartition(row, sources) {
			system[path] = true
			if err := backing(path); err != nil {
				return nil, nil, err
			}
		}
	}
	for path := range system {
		delete(carriers, path)
	}
	return system, carriers, nil
}
