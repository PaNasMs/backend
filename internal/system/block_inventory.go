package system

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// BlockDevicesRead only obtains lsblk metadata. It does not run SMART, fsck or
// other device probes; callers use the existing health and temperature caches.
func BlockDevicesRead(ctx context.Context, columns string) ([]map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd, err := BlockDevicesCommand(ctx, "--json", "--bytes", "--output", columns)
	if err != nil {
		return nil, err
	}
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return decodeBlockDevices(raw)
}

func decodeBlockDevices(raw []byte) ([]map[string]any, error) {
	var result struct {
		Devices []map[string]any `json:"blockdevices"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid block device inventory")
	}
	if result.Devices == nil {
		return nil, fmt.Errorf("missing block device inventory")
	}
	return result.Devices, nil
}
