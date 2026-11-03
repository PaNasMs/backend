package localmounts

import (
	"context"
	"os"
	"panasms.local/backend/internal/systemops/folders"
	"path/filepath"
	"testing"
)

func TestEjectMustVerifyMountedBtrfsDescendant(t *testing.T) {
	s := fixtureService(t)
	s.sys = t.TempDir()
	path := filepath.Join(s.sys, "sda", "device")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "delete"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	pf, _ := s.load(context.Background())
	pf.Inventory.Rows["/dev/sda"]["fstype"] = ""
	point := "/mnt/panasms-unavailable-btrfs-child"
	pf.Inventory.Rows["/dev/sda1"] = map[string]any{"kname": "sda1", "type": "part", "fstype": "btrfs", "uuid": "child-uuid", "mountpoints": []any{point}}
	pf.Inventory.Parents["/dev/sda1"] = map[string]bool{"/dev/sda": true}
	s.mounts = func() ([]folders.LiveMount, error) {
		return []folders.LiveMount{{ID: 254, Device: "0:254", Root: "/", Target: point, FSType: "btrfs", Source: "/dev/sda1"}}, nil
	}
	if _, err := s.prepare(context.Background(), "disk.eject", map[string]any{"target": "/dev/sda"}, "admin"); err == nil {
		t.Fatal("unverified mounted Btrfs child was omitted from the ejection plan")
	}
}
