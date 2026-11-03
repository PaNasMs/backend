package partitionfs

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
)

func pinPlan(action string, plan *prepared) ([]*storagebase.PinnedDevice, error) {
	needed := map[string]bool{plan.target: true}
	if strings.HasPrefix(action, "partition.") {
		needed[plan.parent] = true
	}
	if action == "partition.delete" {
		delete(needed, plan.target)
	}
	pins := []*storagebase.PinnedDevice{}
	for _, identity := range plan.identity.Devices {
		if !needed[identity.Path] {
			continue
		}
		pin, err := storagebase.PinDevice(identity)
		if err != nil {
			for _, p := range pins {
				p.Close()
			}
			return nil, err
		}
		pins = append(pins, pin)
		delete(needed, identity.Path)
	}
	if len(needed) != 0 {
		for _, p := range pins {
			p.Close()
		}
		return nil, reject("Could not verify storage identity")
	}
	return pins, nil
}
func pinnedRunner(run runner, pins []*storagebase.PinnedDevice) runner {
	return func(ctx context.Context, args []string, opts systemops.CommandOptions) ([]byte, error) {
		rewritten := append([]string{}, args...)
		if len(args) == 0 {
			return run(ctx, args, opts)
		}
		utility := filepath.Base(args[0])
		useDevice := false
		switch utility {
		case "sfdisk", "parted", "partx", "wipefs", "e2fsck", "resize2fs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "mkfs.vfat":
			useDevice = true
		}
		if useDevice {
			for _, pin := range pins {
				if err := pin.Verify(); err != nil {
					return nil, err
				}
				for i, arg := range rewritten {
					if arg == pin.Identity.Path {
						rewritten[i] = pin.Path()
					}
				}
			}
		}
		data, err := run(ctx, rewritten, opts)
		if err != nil {
			return nil, err
		}
		if utility == "sfdisk" && len(args) > 1 && args[1] == "--json" {
			return canonicalTableNames(data, pins)
		}
		return data, nil
	}
}

var partitionSuffix = regexp.MustCompile(`^p?[1-9][0-9]*$`)

func canonicalTableNames(data []byte, pins []*storagebase.PinnedDevice) ([]byte, error) {
	var value map[string]any
	if err := systemops.Decode(data, &value); err != nil {
		return nil, err
	}
	table, ok := value["partitiontable"].(map[string]any)
	if !ok {
		return nil, reject("Could not read the partition table. No changes were made.")
	}
	for _, pin := range pins {
		if text(table, "device") != pin.Path() {
			continue
		}
		table["device"] = pin.Identity.Path
		parts, err := tableParts(table)
		if err != nil {
			return nil, err
		}
		for _, part := range parts {
			node := text(part, "node")
			if strings.HasPrefix(node, pin.Identity.Path) {
				suffix := strings.TrimPrefix(node, pin.Identity.Path)
				last := pin.Identity.Path[len(pin.Identity.Path)-1]
				if last >= '0' && last <= '9' {
					if !strings.HasPrefix(suffix, "p") {
						return nil, reject("Could not verify partition device names")
					}
				}
				if !partitionSuffix.MatchString(suffix) {
					return nil, reject("Could not verify partition device names")
				}
				continue
			}
			suffix := strings.TrimPrefix(node, pin.Path())
			if suffix == node || !partitionSuffix.MatchString(suffix) {
				return nil, reject("Could not verify partition device names")
			}
			number := strings.TrimPrefix(suffix, "p")
			separator := ""
			last := pin.Identity.Path[len(pin.Identity.Path)-1]
			if last >= '0' && last <= '9' {
				separator = "p"
			}
			part["node"] = pin.Identity.Path + separator + number
		}
	}
	return json.Marshal(value)
}
