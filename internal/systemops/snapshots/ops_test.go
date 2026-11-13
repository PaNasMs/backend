package snapshots

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"panasms.local/backend/internal/systemops"
)

func TestBtrfsVolumeRequestABI(t *testing.T) {
	var args volumeArgs
	if unsafe.Sizeof(args) != 4096 || unsafe.Offsetof(args.Name) != 56 ||
		unsafe.Offsetof(args.Flags) != 16 || snapshotCreateV2 != 0x50009417 || snapshotDestroyV2 != 0x5000943f {
		t.Fatal("snapshot ioctl payload does not match linux/btrfs.h")
	}
}
func TestDestinationCannotOverwriteDanglingSymlinkOrExistingFile(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err = requireAbsent(dir, "new"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("missing", filepath.Join(dir.Name(), "dangling")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir.Name(), "data"), []byte("survives"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dangling", "data"} {
		if err = requireAbsent(dir, name); !systemops.IsRejected(err) {
			t.Fatalf("%s not rejected: %v", name, err)
		}
	}
}
func TestRecoveryUnavailableNeverRetries(t *testing.T) {
	report, err := Recovery(context.Background(), "/dev/missing-snapshot-test", map[string]any{"snapshot": "before", "name": "copy"})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Checks         []map[string]any
		Route, Message string
		RecoveryAction any
	}
	if err = json.Unmarshal(report, &result); err != nil {
		t.Fatal(err)
	}
	if result.Route != "/storage/mounts" || result.RecoveryAction != nil || len(result.Checks) < 2 || result.Message == "" {
		t.Fatal(string(report))
	}
}
