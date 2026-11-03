package partitionfs

import (
	"encoding/json"
	"os"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
	"testing"
)

func TestPinnedTableNamesResolveOnlyExpectedPartitionSuffix(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "descriptor")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, target := range []string{"/dev/sda", "/dev/loop0"} {
		pin := &storagebase.PinnedDevice{File: file, Identity: storagequery.DeviceIdentity{Path: target}}
		for _, suffix := range []string{"p1", "p12"} {
			raw, _ := json.Marshal(map[string]any{"partitiontable": map[string]any{"device": pin.Path(), "partitions": []any{map[string]any{"node": pin.Path() + suffix, "start": 2048, "size": 4096}}}})
			data, err := canonicalTableNames(raw, []*storagebase.PinnedDevice{pin})
			if err != nil {
				t.Fatal(err)
			}
			var value map[string]any
			if err = json.Unmarshal(data, &value); err != nil {
				t.Fatal(err)
			}
			table := value["partitiontable"].(map[string]any)
			parts, _ := tableParts(table)
			want := target + suffix
			if target == "/dev/sda" {
				want = target + suffix[1:]
			}
			if text(table, "device") != target || text(parts[0], "node") != want {
				t.Fatalf("%s", data)
			}
		}
		for _, node := range []string{pin.Path() + "p0", pin.Path() + "p1/../../dev/sdb", target + "evil"} {
			raw, _ := json.Marshal(map[string]any{"partitiontable": map[string]any{"device": pin.Path(), "partitions": []any{map[string]any{"node": node}}}})
			if _, err := canonicalTableNames(raw, []*storagebase.PinnedDevice{pin}); err == nil {
				t.Fatalf("unexpected partition path accepted: %s", node)
			}
		}
	}
}
