package storagequery

import (
	"encoding/json"
	"fmt"
	"panasms.local/backend/internal/systemops"
	"sort"
	"strings"
)

type Preflight struct {
	Inventory        *Inventory
	System, Carriers map[string]bool
	Holders          func(string) ([]string, error)
}

func (p *Preflight) Protected(path string, layout bool) error {
	row, exists := p.Inventory.Rows[path]
	if !exists {
		return rejectf("The device no longer exists")
	}
	if p.System[path] {
		return rejectf("The system partition is protected")
	}
	if p.Carriers[path] {
		allowed := false
		if layout {
			switch row["type"] {
			case "disk", "loop", "md", "raid0", "raid1", "raid5", "raid6", "raid10":
				allowed = true
			}
		}
		if !allowed {
			return rejectf("The system drive or one of its members is protected")
		}
	}
	if readOnly(row["ro"]) {
		return rejectf("The device is read-only")
	}
	return nil
}

func readOnly(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case json.Number:
		return v != "0"
	case float64:
		return v != 0
	case string:
		return v != "" && v != "0"
	}
	return false
}

func mounted(row map[string]any) bool {
	mounts, _ := row["mountpoints"].([]any)
	for _, point := range mounts {
		if value, ok := point.(string); ok && value != "" {
			return true
		}
	}
	return false
}

func (p *Preflight) Unused(path string, allowChildren bool) error {
	if p.Inventory.Rows[path] == nil {
		return rejectf("The device no longer exists")
	}
	paths := p.Inventory.Descendants(path)
	if !allowChildren && len(paths) != 1 {
		return rejectf("Detach dependent devices or delete partitions first")
	}
	for _, child := range paths {
		if mounted(p.Inventory.Rows[child]) {
			return rejectf("Unmount file systems first")
		}
	}
	for _, child := range paths {
		row := p.Inventory.Rows[child]
		if child != path && row["type"] != "disk" && row["type"] != "part" {
			return rejectf("The drive is used by an array or another storage layer")
		}
		holders, err := p.Holders(row["kname"].(string))
		if err != nil {
			return rejectf("Could not verify storage dependencies. No changes were made.")
		}
		if len(holders) > 0 {
			sort.Strings(holders)
			return rejectf("Device %s is used by: %s", child, strings.Join(holders, ", "))
		}
	}
	return nil
}

func (p *Preflight) Layout(path string) error {
	if err := p.Protected(path, true); err != nil {
		return err
	}
	row := p.Inventory.Rows[path]
	if fs, _ := row["fstype"].(string); fs != "" {
		return rejectf("The device contains a file system")
	}
	if mounted(row) {
		return rejectf("Unmount file systems first")
	}
	holders, err := p.Holders(row["kname"].(string))
	if err != nil {
		return rejectf("Could not verify storage dependencies. No changes were made.")
	}
	if len(holders) > 0 {
		return rejectf("The drive is used by an array or another storage layer")
	}
	return nil
}

func rejectf(format string, args ...any) error {
	return &systemops.Rejected{Message: fmt.Sprintf(format, args...)}
}
