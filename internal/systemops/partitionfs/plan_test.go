package partitionfs

import (
	"context"
	"encoding/json"
	"os"
	"panasms.local/backend/internal/systemops/storagequery"
	"testing"
)

func planningFixture(t *testing.T) (*service, *storagequery.Preflight) {
	s, p := fixture(t, `{"signatures":[{"type":"gpt"}]}`, validTable)
	s.root = t.TempDir()
	if err := os.Chmod(s.root, 0700); err != nil {
		t.Fatal(err)
	}
	s.owner = os.Getuid()
	s.identity = func(_ *storagequery.Preflight, target string) (storagequery.StorageIdentity, error) {
		return storagequery.StorageIdentity{BootID: "12345678-1234-1234-1234-123456789abc", Devices: []storagequery.DeviceIdentity{{Path: target, DeviceNumber: "8:1", DiskSequence: "42"}}}, nil
	}
	s.config = func() (string, error) { return "# retained configuration\n", nil }
	s.find = func(name string) (string, error) { return "/usr/sbin/" + name, nil }
	p.Inventory.Rows["/dev/sda1"]["partn"] = json.Number("1")
	return s, p
}
func TestPartitionCreatePlanProtectsNeighboursAndFingerprintsEpoch(t *testing.T) {
	s, p := planningFixture(t)
	params := map[string]any{"target": "/dev/sda", "startMiB": json.Number("4"), "endMiB": json.Number("6")}
	a, err := s.prepareTarget(context.Background(), "partition.create", params, p, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	params["startMiB"] = json.Number("2")
	if _, err := s.prepareTarget(context.Background(), "partition.create", params, p, "/dev/sda"); err == nil {
		t.Fatal("overlapping partition accepted")
	}
	params["startMiB"] = json.Number("4")
	s.identity = func(_ *storagequery.Preflight, target string) (storagequery.StorageIdentity, error) {
		return storagequery.StorageIdentity{BootID: "87654321-1234-1234-1234-123456789abc", Devices: []storagequery.DeviceIdentity{{Path: target, DeviceNumber: "8:1", DiskSequence: "42"}}}, nil
	}
	b, err := s.prepareTarget(context.Background(), "partition.create", params, p, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	if a.fingerprint == b.fingerprint {
		t.Fatal("plan survives reboot identity change")
	}
	p.System["/dev/sda"] = true
	if _, err := s.prepareTarget(context.Background(), "partition.create", params, p, "/dev/sda"); err == nil {
		t.Fatal("system device accepted")
	}
}
func TestFilesystemPlansRejectProtectedMountedAndContainerDevices(t *testing.T) {
	for _, action := range []string{"filesystem.format", "filesystem.remove"} {
		t.Run(action, func(t *testing.T) {
			s, p := planningFixture(t)
			row := p.Inventory.Rows["/dev/sda1"]
			row["fstype"] = "ext4"
			params := map[string]any{"target": "/dev/sda1", "format": "ext4"}
			if _, err := s.prepareTarget(context.Background(), action, params, p, "/dev/sda1"); err != nil {
				t.Fatal(err)
			}
			row["mountpoints"] = []any{"/mnt/data"}
			if _, err := s.prepareTarget(context.Background(), action, params, p, "/dev/sda1"); err == nil {
				t.Fatal("mounted filesystem accepted")
			}
			row["mountpoints"] = []any{}
			row["fstype"] = "linux_raid_member"
			if _, err := s.prepareTarget(context.Background(), action, params, p, "/dev/sda1"); err == nil {
				t.Fatal("RAID member accepted")
			}
			row["fstype"] = "ext4"
			p.System["/dev/sda1"] = true
			if _, err := s.prepareTarget(context.Background(), action, params, p, "/dev/sda1"); err == nil {
				t.Fatal("system filesystem accepted")
			}
		})
	}
}
func TestUnknownActionAndInvalidGeometryAreRejected(t *testing.T) {
	s, p := planningFixture(t)
	if _, err := s.prepareTarget(context.Background(), "raid.create", nil, p, "/dev/sda"); err == nil {
		t.Fatal("scope escaped")
	}
	for _, v := range []any{true, "16", json.Number("1.5"), json.Number("-1"), json.Number("18446744073709551616")} {
		if _, err := integer(map[string]any{"sizeMiB": v}, "sizeMiB", 0, 100); err == nil {
			t.Fatalf("accepted %v", v)
		}
	}
}
