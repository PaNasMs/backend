package system

import (
	"context"
	"encoding/json"
	"fmt"
)

// BlockDevicesRead only obtains lsblk metadata. It does not run SMART, fsck or
// other device probes; callers use the existing health and temperature caches.
func BlockDevicesRead(ctx context.Context, columns string) ([]map[string]any, error) {
	raw, err := command(ctx, "/usr/bin/lsblk", "--json", "--bytes", "--output", columns)
	if err != nil {
		return nil, err
	}
	return decodeBlockDevices(raw)
}

func decodeBlockDevices(raw []byte) ([]map[string]any, error) {
	var result struct {
		Devices []map[string]any `json:"blockdevices"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if result.Devices == nil {
		return nil, fmt.Errorf("missing block device inventory")
	}
	return result.Devices, nil
}
