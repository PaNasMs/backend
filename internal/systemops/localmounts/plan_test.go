package localmounts

import (
	"context"
	"os"
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
	"path/filepath"
	"testing"
)

func fixtureService(t *testing.T) *service {
	t.Helper()
	root := t.TempDir()
	os.Chmod(root, 0700)
	row := map[string]any{"path": "/dev/sda", "kname": "sda", "type": "disk", "fstype": "ext4", "uuid": "test-uuid", "mountpoints": []any{}}
	inv := &storagequery.Inventory{Rows: map[string]map[string]any{"/dev/sda": row}, Parents: map[string]map[string]bool{"/dev/sda": {}}}
	pf := &storagequery.Preflight{Inventory: inv, Holders: func(string) ([]string, error) { return nil, nil }}
	return &service{owner: os.Getuid(), root: filepath.Join(root, "journals"), load: func(context.Context) (*storagequery.Preflight, error) { return pf, nil }, resolve: func(path string) (string, error) { return path, nil }, identity: func(_ *storagequery.Preflight, path string) (storagequery.StorageIdentity, error) {
		return storagequery.StorageIdentity{BootID: "boot", Devices: []storagequery.DeviceIdentity{{Path: path, DeviceNumber: "8:0", DiskSequence: "1", UUID: "test-uuid"}}}, nil
	}, mounts: func() ([]folders.LiveMount, error) { return nil, nil }, fstab: func() (string, error) { return "# preserved\n", nil }, witness: func(string) (storagebase.TargetWitness, error) {
		return storagebase.TargetWitness{Ancestor: "/mnt", Device: 1, Inode: 2, MountID: 3}, nil
	}, blockers: func(context.Context, []folders.LiveMount, []folders.LiveMount) error { return nil }, tool: func(string) bool { return true }}
}
func TestPlanBindsBootMountAndFstabState(t *testing.T) {
	s := fixtureService(t)
	params := map[string]any{"target": "/dev/sda", "point": "/mnt/data"}
	ctx := context.Background()
	first, err := s.prepare(ctx, "mount.attach", params, "alice")
	if err != nil {
		t.Fatal(err)
	}
	s.fstab = func() (string, error) { return "# edited\n", nil }
	next, err := s.prepare(ctx, "mount.attach", params, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if first.fingerprint == next.fingerprint {
		t.Fatal("fstab edit omitted")
	}
	s.identity = func(_ *storagequery.Preflight, path string) (storagequery.StorageIdentity, error) {
		return storagequery.StorageIdentity{BootID: "newboot", Devices: []storagequery.DeviceIdentity{{Path: path, DeviceNumber: "8:0", DiskSequence: "1"}}}, nil
	}
	third, err := s.prepare(ctx, "mount.attach", params, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if next.fingerprint == third.fingerprint {
		t.Fatal("boot omitted")
	}
}
func TestPlanRejectsForeignOccupiedMountAndProtectedDisk(t *testing.T) {
	s := fixtureService(t)
	s.mounts = func() ([]folders.LiveMount, error) {
		return []folders.LiveMount{{ID: 4, Device: "8:16", Target: "/mnt/data"}}, nil
	}
	if _, err := s.prepare(context.Background(), "mount.attach", map[string]any{"target": "/dev/sda", "point": "/mnt/data"}, "alice"); err == nil {
		t.Fatal("foreign mount accepted")
	}
	pf, _ := s.load(context.Background())
	pf.System = map[string]bool{"/dev/sda": true}
	if _, err := s.prepare(context.Background(), "disk.prepare", map[string]any{"target": "/dev/sda"}, "alice"); err == nil {
		t.Fatal("system disk accepted")
	}
}
func TestPlanDetachDeepestFirst(t *testing.T) {
	s := fixtureService(t)
	s.mounts = func() ([]folders.LiveMount, error) {
		return []folders.LiveMount{{ID: 1, Device: "8:0", Target: "/mnt/data"}, {ID: 2, Device: "8:0", Target: "/mnt/data/child"}}, nil
	}
	p, err := s.prepare(context.Background(), "mount.detach", map[string]any{"target": "/dev/sda"}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if p.selected[0].ID != 2 || p.selected[1].ID != 1 {
		t.Fatal(p.selected)
	}
}
