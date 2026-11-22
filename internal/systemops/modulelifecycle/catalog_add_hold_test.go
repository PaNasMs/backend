package modulelifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestForeignPublisherHoldFencesOnlyItsSigner(t *testing.T) {
	c, serve := catalogFixture(t)
	dir, err := trustedDirectory(c.root, c.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	path := filepath.Join(c.root, failedAddName("pending"))
	if err := os.Symlink("operator-owned", path); err != nil {
		t.Fatal(err)
	}
	if err := c.holdFailedAdd(dir, "pending"); err != nil {
		t.Fatal(err)
	}
	if fenced, err := c.publisherFenced("pending"); err != nil || !fenced {
		t.Fatalf("publisher fence: %v %v", fenced, err)
	}
	if err := c.clearFailedAdd(dir, "pending"); !errors.Is(err, errForeignPublisherHold) {
		t.Fatalf("clearing foreign entry returned %v", err)
	}
	if target, err := os.Readlink(path); err != nil || target != "operator-owned" {
		t.Fatalf("foreign symlink changed: %q %v", target, err)
	}
	serve("2.0.0", true)
	visibleCatalog(t, c, "2.0.0", false)
}

func TestPublisherHoldTransitionsPreserveInode(t *testing.T) {
	c, _ := catalogFixture(t)
	dir, err := trustedDirectory(c.root, c.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	const signer = "fixture"
	path := filepath.Join(c.root, failedAddName(signer))
	var first os.FileInfo
	for _, want := range []bool{true, false, true} {
		if want {
			err = c.holdFailedAdd(dir, signer)
		} else {
			err = c.clearFailedAdd(dir, signer)
		}
		if err != nil {
			t.Fatal(err)
		}
		fenced, err := c.publisherFenced(signer)
		if err != nil || fenced != want {
			t.Fatalf("expected fenced=%v, got %v, %v", want, fenced, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = info
		} else if !os.SameFile(first, info) {
			t.Fatal("publisher hold inode changed during transition")
		}
	}
}

func TestPublisherHoldPreservesAnotherSignersRecord(t *testing.T) {
	c, _ := catalogFixture(t)
	dir, err := trustedDirectory(c.root, c.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	path := filepath.Join(c.root, failedAddName("pending"))
	foreign := failedAddRecord("another", publisherReleased)
	if err := os.WriteFile(path, []byte(foreign), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.holdFailedAdd(dir, "pending"); err != nil {
		t.Fatal(err)
	}
	if err := c.clearFailedAdd(dir, "pending"); !errors.Is(err, errForeignPublisherHold) {
		t.Fatalf("unexpected release result: %v", err)
	}
	if fenced, err := c.publisherFenced("pending"); err != nil || !fenced {
		t.Fatalf("foreign record should fence the publisher: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != foreign {
		t.Fatalf("foreign record changed: %v", err)
	}
}
