package storagequery

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIdentityRejectsReusedNameAndMissingDependencies(t *testing.T) {
	inv := fixtureInventory(t, `[{"path":"/dev/sda","kname":"sda","type":"disk","uuid":"data"}]`)
	sys := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sys, "sda/slaves"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{"sda/dev": "8:0", "sda/diskseq": "10"} {
		if err := os.WriteFile(filepath.Join(sys, path), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	first, err := inv.Identity("/dev/sda", sys)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sys, "sda/diskseq"), []byte("11"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := inv.Identity("/dev/sda", sys)
	if err != nil || reflect.DeepEqual(first, second) {
		t.Fatalf("%v %v %v", first, second, err)
	}
	if err := os.Mkdir(filepath.Join(sys, "sda/slaves/gone"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Identity("/dev/sda", sys); err == nil {
		t.Fatal("disappeared backing device accepted")
	}
}

func TestPartitionIdentityUsesParentIncarnationWithoutSlavesDirectory(t *testing.T) {
	root := t.TempDir()
	sys := filepath.Join(root, "class/block")
	disk := filepath.Join(root, "devices/sda")
	partition := filepath.Join(disk, "sda1")
	for _, dir := range []string{sys, filepath.Join(disk, "slaves"), filepath.Join(partition, "holders")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, data := range map[string]string{filepath.Join(disk, "diskseq"): "20", filepath.Join(disk, "dev"): "8:0", filepath.Join(partition, "partition"): "1", filepath.Join(partition, "dev"): "8:1"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"sda": disk, "sda1": partition} {
		if err := os.Symlink(target, filepath.Join(sys, name)); err != nil {
			t.Fatal(err)
		}
	}
	inv := fixtureInventory(t, `[{"path":"/dev/sda","kname":"sda","type":"disk","children":[{"path":"/dev/sda1","kname":"sda1","type":"part"}]}]`)
	identity, err := inv.Identity("/dev/sda1", sys)
	if err != nil || len(identity) != 2 || identity[1].DeviceNumber != "8:1" || identity[1].DiskSequence != "20" {
		t.Fatalf("%v %v", identity, err)
	}
	if err := os.Remove(filepath.Join(partition, "partition")); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Identity("/dev/sda1", sys); err == nil {
		t.Fatal("missing whole-device dependencies accepted")
	}
}

func TestIdentityRejectsMissingSlavesWithoutPartitionMarker(t *testing.T) {
	inv := fixtureInventory(t, `[{"path":"/dev/sda","kname":"sda","type":"disk"}]`)
	sys := t.TempDir()
	node := filepath.Join(sys, "sda")
	if err := os.Mkdir(node, 0700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"dev": "8:0", "diskseq": "42"} {
		if err := os.WriteFile(filepath.Join(node, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := inv.Identity("/dev/sda", sys)
	pathError, ok := err.(*os.PathError)
	if !ok || !os.IsNotExist(err) || pathError.Path != filepath.Join(node, "slaves") {
		t.Fatalf("expected missing slaves rejection, got %v", err)
	}
	if err := os.Mkdir(filepath.Join(node, "slaves"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Identity("/dev/sda", sys); err != nil {
		t.Fatal(err)
	}
}
