package storagequery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnavailableUdevMetadataIsNotBlankFilesystem(t *testing.T) {
	root := t.TempDir()
	rows := []map[string]any{{"maj:min": "8:0", "fstype": nil, "children": []any{map[string]any{"maj:min": "8:1", "fstype": nil}}}}
	if err := requireMetadataCache(rows, root); err == nil {
		t.Fatal("missing cache accepted")
	}
	for _, name := range []string{"b8:0", "b8:1"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("I:123\nE:TAGS=:systemd:\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := requireMetadataCache(rows, root); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{"", "I:0\n", "I:invalid\n", "E:ID_FS_TYPE=ext4\n"} {
		if err := os.WriteFile(filepath.Join(root, "b8:1"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if err := requireMetadataCache(rows, root); err == nil {
			t.Fatalf("uninitialized cache %q accepted", data)
		}
	}
	rows[0]["maj:min"] = "../../etc/passwd"
	if err := requireMetadataCache(rows, root); err == nil {
		t.Fatal("invalid device number accepted")
	}
}
