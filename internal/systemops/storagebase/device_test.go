package storagebase

import (
	"os"
	"panasms.local/backend/internal/systemops/storagequery"
	"path/filepath"
	"testing"
)

func TestPinDeviceRefusesCharacterDeviceAndNoncanonicalPath(t *testing.T) {
	for _, path := range []string{"/dev/null", "/dev/../dev/null", "/dev/disk/by-id/foreign"} {
		f, err := PinDevice(storagequery.DeviceIdentity{Path: path, DeviceNumber: "1:3"})
		if err == nil {
			f.Close()
			t.Fatalf("accepted %s", path)
		}
	}
}

func TestPublishedPartitionMustStillBelongToTheSameDiskSequence(t *testing.T) {
	sys := t.TempDir()
	disk := filepath.Join(sys, "devices", "sda")
	part := filepath.Join(disk, "sda1")
	index := filepath.Join(sys, "dev", "block")
	for _, dir := range []string{part, index} {
		if e := os.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	write := func(p, v string) {
		t.Helper()
		if e := os.WriteFile(p, []byte(v), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(filepath.Join(part, "dev"), "8:1\n")
	write(filepath.Join(part, "partition"), "1\n")
	write(filepath.Join(disk, "diskseq"), "31\n")
	entry := filepath.Join(index, "8:1")
	if e := os.Symlink(part, entry); e != nil {
		t.Fatal(e)
	}
	id := storagequery.DeviceIdentity{DeviceNumber: "8:1", DiskSequence: "31"}
	if e := verifyPublishedDevice(id, index); e != nil {
		t.Fatal(e)
	}
	write(filepath.Join(disk, "diskseq"), "32\n")
	if e := verifyPublishedDevice(id, index); e == nil {
		t.Fatal("reused device number accepted")
	}
	if e := os.Remove(entry); e != nil {
		t.Fatal(e)
	}
	if e := verifyPublishedDevice(id, index); e == nil {
		t.Fatal("unpublished device accepted")
	}
}
