package localmounts

import (
	"context"
	"testing"
)

func TestForeignDuplicateUUIDPreservesConfiguredVolume(t *testing.T) {
	s := fixtureService(t)
	p, _ := s.load(context.Background())
	p.Inventory.Rows["/dev/sdb"] = map[string]any{"path": "/dev/sdb", "kname": "sdb", "type": "disk", "fstype": "ext4", "uuid": "test-uuid", "mountpoints": []any{}}
	p.Inventory.Parents["/dev/sdb"] = map[string]bool{}
	s.fstab = func() (string, error) {
		return "UUID=test-uuid /mnt/retained ext4 noauto,x-systemd.device-timeout=30s 0 2\n", nil
	}
	for _, action := range []string{"disk.prepare", "mount.attach", "mount.open", "mount.settings"} {
		_, e := s.prepare(context.Background(), action, map[string]any{"target": "/dev/sda", "point": "/mnt/data"}, "admin")
		if e == nil || e.Error() != "This file system UUID is present on another device. Review the mount configuration." {
			t.Errorf("%s accepted ambiguous persistent volume owner", action)
		}
	}
	s.fstab = func() (string, error) { return "# unrelated configuration\n", nil }
	if _, err := s.prepare(context.Background(), "disk.prepare", map[string]any{"target": "/dev/sda"}, "admin"); err != nil {
		t.Fatalf("unreferenced duplicate UUID prevented preparing the selected disk: %v", err)
	}
}
