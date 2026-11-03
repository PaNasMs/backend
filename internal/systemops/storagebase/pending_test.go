package storagebase

import (
	"encoding/json"
	"os"
	"panasms.local/backend/internal/systemops/storagequery"
	"path/filepath"
	"testing"
)

func TestPendingOtherDomainBlocksAcrossBoots(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	roots := []PendingRoot{{root, "partitionfs"}}
	old := storagequery.StorageIdentity{BootID: "old", Devices: []storagequery.DeviceIdentity{{Path: "/dev/sda", DeviceNumber: "8:0", DiskSequence: "11"}}}
	current := old
	current.BootID = "new"
	record := TransactionEnvelope{Schema: 1, Domain: "partitionfs", Action: "partition.create", Target: "/dev/sda", Identity: old, Phase: "pending"}
	save := func() {
		t.Helper()
		data, _ := json.Marshal(record)
		if err := os.WriteFile(filepath.Join(root, "disk.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	save()
	if err := checkPendingRoots(roots, os.Getuid(), "localmounts", "/dev/sda", current); err == nil {
		t.Fatal("pending operation ignored across boot")
	}
	if err := checkPendingRoots(roots, os.Getuid(), "partitionfs", "/dev/sda", current); err != nil {
		t.Fatal(err)
	}
	if err := checkPendingRoots(roots, os.Getuid(), "partitionfs", "/dev/sda1", current); err == nil {
		t.Fatal("own-domain parent journal bypassed by child operation")
	}
	current.Devices = []storagequery.DeviceIdentity{{Path: "/dev/sdb", DeviceNumber: "8:16", DiskSequence: "12"}}
	if err := checkPendingRoots(roots, os.Getuid(), "localmounts", "/dev/sda", current); err != nil {
		t.Fatal(err)
	}
	record.Phase = "complete"
	save()
	if err := checkPendingRoots(roots, os.Getuid(), "localmounts", "/dev/sda", old); err != nil {
		t.Fatal(err)
	}
	record.Schema = 2
	save()
	if err := checkPendingRoots(roots, os.Getuid(), "localmounts", "/dev/sda", current); err == nil {
		t.Fatal("unknown complete schema ignored")
	}
}
func TestPendingRejectsLinksAndMalformedEvidence(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	roots := []PendingRoot{{root, "partitionfs"}}
	path := filepath.Join(root, "disk.json")
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	if err := checkPendingRoots(roots, os.Getuid(), "localmounts", "/dev/sda", storagequery.StorageIdentity{}); err == nil {
		t.Fatal("symlink followed")
	}
	os.Remove(path)
	os.WriteFile(path, []byte("{"), 0600)
	if err := checkPendingRoots(roots, os.Getuid(), "localmounts", "/dev/sda", storagequery.StorageIdentity{}); err == nil {
		t.Fatal("malformed journal ignored")
	}
}

func TestPendingIgnoresOnlyTrustedUncommittedWriterTemps(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	roots := []PendingRoot{{root, "partitionfs"}}
	for _, name := range []string{".journal-partial", ".panasms-partial"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("{partial"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkPendingRoots(roots, os.Getuid(), "localmounts", "/dev/sda", storagequery.StorageIdentity{}); err != nil {
		t.Fatal(err)
	}
	os.Symlink("/dev/null", filepath.Join(root, ".journal-link"))
	if err := checkPendingRoots(roots, os.Getuid(), "localmounts", "/dev/sda", storagequery.StorageIdentity{}); err == nil {
		t.Fatal("unsafe temp ignored")
	}
}
