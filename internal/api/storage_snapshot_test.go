package api

import (
	"encoding/json"
	"testing"

	"panasms.local/backend/internal/system"
)

func TestDiskSnapshotPreservesInventoryNumberSize(t *testing.T) {
	for _, size := range []any{json.Number("1000000"), float64(1000000)} {
		result := diskSnapshots(system.Storage{Devices: []map[string]any{{"type": "disk", "path": "/dev/test", "size": size}}})
		if result["/dev/test:"].Size != 1000000 {
			t.Fatalf("%v", result)
		}
	}
}
