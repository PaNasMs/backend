package localmounts

import (
	"context"
	"os"
	"panasms.local/backend/internal/systemops/storagequery"
	"path/filepath"
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

func TestPreparePreservesAlternateFstabSources(t *testing.T) {
	s := fixtureService(t)
	pf, _ := s.load(context.Background())
	row := pf.Inventory.Rows["/dev/sda"]
	row["label"] = "My Disk"
	row["partuuid"] = "1234"
	row["type"] = "part"
	s.sys = t.TempDir()
	if err := os.Mkdir(filepath.Join(s.sys, "sda"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.sys, "sda", "uevent"), []byte("PARTNAME=My Partition\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s.resolve = func(source string) (string, error) {
		if source == "/dev/disk/by-id/test" {
			return "/dev/sda", nil
		}
		return source, nil
	}
	selected := map[string]storagequery.StorageIdentity{"/dev/sda": {}}
	for _, source := range []string{"/dev/sda", "/dev/disk/by-id/test", `LABEL="My\040Disk"`, "PARTUUID=1234", `PARTLABEL=My\040Partition`, `UUID="test-uuid"`} {
		if err := s.checkPrepareSources(source+" /mnt/custom auto defaults 0 0", pf, selected); err == nil || err.Error() != externalConfig {
			t.Errorf("%s: %v", source, err)
		}
	}
	for _, source := range []string{"UUID=test-uuid", "/dev/sdb", "LABEL=Other", "PARTLABEL=Other", "PARTUUID=5678"} {
		if err := s.checkPrepareSources(source+" /mnt/other auto defaults 0 0", pf, selected); err != nil {
			t.Errorf("%s: %v", source, err)
		}
	}
}
