package storagequery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestUnavailableUdevMetadataIsNotBlankFilesystem(t *testing.T) {
	root := t.TempDir()
	rows := []map[string]any{{"maj:min": "8:0", "fstype": nil, "children": []any{map[string]any{"maj:min": "8:1", "fstype": nil}}}}
	check := func() error {
		snapshot, err := readMetadataSnapshot(root)
		if err != nil {
			return err
		}
		return requireMetadataCache(rows, snapshot, snapshot)
	}

	if err := check(); err == nil {
		t.Fatal("missing cache accepted")
	}
	for _, name := range []string{"b8:0", "b8:1"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("I:123\nE:TAGS=:systemd:\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := check(); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{"", "I:0\n", "I:invalid\n", "E:ID_FS_TYPE=ext4\n"} {
		if err := os.WriteFile(filepath.Join(root, "b8:1"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if err := check(); err == nil {
			t.Fatalf("uninitialized cache %q accepted", data)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "b8:1"), []byte("I:123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil {
		t.Fatal(err)
	}
	rows[0]["maj:min"] = "../../etc/passwd"
	if err := check(); err == nil {
		t.Fatal("invalid device number accepted")
	}
}

func TestKnownFilesystemAndProtectedMetadataCannotBecomeBlank(t *testing.T) {
	properties := map[string]string{"fstype": "ID_FS_TYPE=ext4", "uuid": "ID_FS_UUID=data", "label": "ID_FS_LABEL_ENC=Root\\x20Disk", "partuuid": "ID_PART_ENTRY_UUID=part", "parttype": "ID_PART_ENTRY_TYPE=0xef"}
	for field, property := range properties {
		snapshot := map[string][]byte{"8:0": []byte("I:123\nE:" + property + "\n")}
		row := map[string]any{"maj:min": "8:0", field: nil}
		if err := requireMetadataCache([]map[string]any{row}, snapshot, snapshot); err == nil {
			t.Fatalf("missing %s accepted", field)
		}
		expected := map[string]string{"fstype": "ext4", "uuid": "data", "label": "Root Disk", "partuuid": "part", "parttype": "0xef"}[field]
		row[field] = expected
		if err := requireMetadataCache([]map[string]any{row}, snapshot, snapshot); err != nil {
			t.Fatalf("%s: %v", field, err)
		}
	}
}

func TestInventoryRejectsUdevCacheChangesDuringRead(t *testing.T) {
	for _, createDuringRead := range []bool{false, true} {
		root := t.TempDir()
		path := filepath.Join(root, "b8:0")
		if !createDuringRead {
			if err := os.WriteFile(path, []byte("I:123\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		_, err := observedBlockInventory(context.Background(), root, func(context.Context) ([]map[string]any, error) {
			if err := os.WriteFile(path, []byte("I:124\nE:ID_FS_TYPE=ext4\n"), 0600); err != nil {
				t.Fatal(err)
			}
			return []map[string]any{{"maj:min": "8:0", "fstype": nil}}, nil
		})
		if err == nil {
			t.Fatal("changed cache accepted")
		}
	}
}
