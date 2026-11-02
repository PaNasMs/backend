package storagequery

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func fixtureInventory(t *testing.T, text string) *Inventory {
	t.Helper()
	var devices []map[string]any
	if err := json.Unmarshal([]byte(text), &devices); err != nil {
		t.Fatal(err)
	}
	inv, err := NewInventory(devices, func(path string) (string, error) { return path, nil })
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestRepeatedArrayKeepsEveryBackingDisk(t *testing.T) {
	inv := fixtureInventory(t, `[
 {"path":"/dev/sda","kname":"sda","type":"disk","children":[{"path":"/dev/md0","kname":"md0","type":"raid1","mountpoints":["/"]}]},
 {"path":"/dev/sdb","kname":"sdb","type":"disk","children":[{"path":"/dev/md0","kname":"md0","type":"raid1","mountpoints":["/"]}]},
 {"path":"/dev/sdc","kname":"sdc","type":"disk","tran":"usb","mountpoints":[]} ]`)
	system, carriers, err := inv.Protection(nil, func(string) ([]string, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(system, map[string]bool{"/dev/md0": true}) || !reflect.DeepEqual(carriers, map[string]bool{"/dev/sda": true, "/dev/sdb": true}) {
		t.Fatalf("system=%v carriers=%v", system, carriers)
	}
	for _, disk := range []string{"/dev/sda", "/dev/sdb"} {
		got := inv.Descendants(disk)
		if len(got) != 2 || got[0] != "/dev/md0" {
			t.Fatalf("%s descendants %v", disk, got)
		}
	}
}

func TestSystemProtectionUsesKernelSlavesAndFailsClosed(t *testing.T) {
	inv := fixtureInventory(t, `[{"path":"/dev/sda","kname":"sda","type":"disk"},{"path":"/dev/dm-0","kname":"dm-0","type":"crypt","mountpoints":["/var/lib"]}]`)
	_, carriers, err := inv.Protection(nil, func(name string) ([]string, error) {
		if name == "dm-0" {
			return []string{"sda"}, nil
		}
		return nil, nil
	})
	if err != nil || !carriers["/dev/sda"] {
		t.Fatalf("%v %v", carriers, err)
	}
	for _, failure := range []func(string) ([]string, error){
		func(string) ([]string, error) { return nil, errors.New("sysfs unavailable") },
		func(string) ([]string, error) { return []string{"gone"}, nil },
	} {
		if _, _, err := inv.Protection(nil, failure); err == nil {
			t.Fatal("missing evidence accepted")
		}
	}
}

func TestSystemMountComponentBoundariesAndFstab(t *testing.T) {
	for _, point := range []string{"/", "/home/users", "/var/lib", "[SWAP]", "/boot/efi"} {
		if !SystemMount(point) {
			t.Fatal(point)
		}
	}
	for _, point := range []string{"", "/srv/data", "/homecoming", "/variable"} {
		if SystemMount(point) {
			t.Fatal(point)
		}
	}
	sources := SystemSources("# ignored\nUUID=root / ext4 defaults 0 1\nPARTUUID=boot /boot vfat defaults 0 0\nLABEL=swap none swap sw 0 0\nUUID=data /srv/data ext4 defaults 0 0\n")
	for field, value := range map[string]string{"uuid": "root", "partuuid": "boot", "label": "swap"} {
		if !SystemPartition(map[string]any{field: value}, sources) {
			t.Fatalf("%s", field)
		}
	}
	if SystemPartition(map[string]any{"uuid": "data"}, sources) {
		t.Fatal("data filesystem protected")
	}
}

func TestInventoryCanonicalAliasAndConflictingIdentity(t *testing.T) {
	rows := []map[string]any{{"path": "/dev/mapper/system", "kname": "dm-0", "type": "crypt"}}
	inv, err := NewInventory(rows, func(string) (string, error) { return "/dev/dm-0", nil })
	if err != nil || inv.Rows["/dev/dm-0"] == nil {
		t.Fatalf("%v %v", inv, err)
	}
	if rows[0]["path"] != "/dev/mapper/system" {
		t.Fatal("input mutated")
	}
	rows = append(rows, map[string]any{"path": "/dev/dm-0", "kname": "dm-0", "type": "disk"})
	if _, err := NewInventory(rows, func(string) (string, error) { return "/dev/dm-0", nil }); err == nil {
		t.Fatal("conflicting identity accepted")
	}
}
