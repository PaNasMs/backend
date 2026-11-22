package modulelifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForeignPublisherHoldFencesOnlyItsSigner(t *testing.T) {
	c, serve := catalogFixture(t)
	dir, err := trustedDirectory(c.root, c.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	path := filepath.Join(c.root, holdPrefix("pending")+strings.Repeat("a", 32))
	if err := os.Symlink("operator-owned", path); err != nil {
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
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if fenced, err := c.publisherFenced("pending"); err != nil || !fenced {
		t.Fatalf("unsuccessful enrollment lost its fence: %v", err)
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
		names, err := publisherHoldNames(dir, signer)
		if err != nil || len(names) != 1 {
			t.Fatalf("expected one hold: %v %v", names, err)
		}
		info, err := os.Stat(filepath.Join(c.root, names[0]))
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
	path := filepath.Join(c.root, holdPrefix("pending")+strings.Repeat("a", 32))
	foreign := failedAddRecord(holdPrefix("another")+strings.Repeat("a", 32), publisherReleased)
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

func TestRollbackRecoversWhenBothHoldPathsAreOccupied(t *testing.T) {
	ctx := context.Background()
	c, serve := catalogFixture(t)
	const signer = "pending"
	const add = "module.source-add"
	params := servePendingRepository(t, &c)
	stopped := errors.New("interrupted before config replacement")
	c.sourceBoundary = func(phase string) error {
		if phase == "key-written" {
			return stopped
		}
		return nil
	}
	if _, err := executePlannedSource(t, c, add, params); !errors.Is(err, stopped) {
		t.Fatal(err)
	}
	dir, err := trustedDirectory(c.root, c.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	names, err := publisherHoldNames(dir, signer)
	if err != nil || len(names) != 1 {
		t.Fatalf("expected the original hold: %v %v", names, err)
	}
	files := []string{names[0], ".source-add-reserve-" + signer, holdPrefix(signer) + strings.Repeat("b", 32)}
	if err := os.Rename(filepath.Join(c.root, names[0]), filepath.Join(c.root, "original.saved")); err != nil {
		t.Fatal(err)
	}
	const contents = "operator's file"
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(c.root, name), []byte(contents), 0400); err != nil {
			t.Fatal(err)
		}
	}
	restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
	if _, err := restarted.recoverCatalog(ctx, add); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.root, sourceIntent)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback retained journal: %v", err)
	}
	serve("2.0.0", true)
	visibleCatalog(t, restarted, "2.0.0", false)
	for _, name := range files {
		file := filepath.Join(c.root, name)
		if err := os.Rename(file, file+".saved"); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(file + ".saved")
		if err != nil || string(raw) != contents {
			t.Fatalf("operator file changed: %v", err)
		}
	}
	if held, err := restarted.publisherFenced(signer); err != nil || !held {
		t.Fatalf("moving operator files released the publisher fence: %v", err)
	}
	if _, err := executePlannedSource(t, restarted, add, params); err != nil {
		t.Fatal(err)
	}
	if held, err := restarted.publisherFenced(signer); err != nil || held {
		t.Fatalf("confirmed publisher still fenced: %v", err)
	}
}

func TestInactivePublisherReportIncludesUnconfiguredSignerAndForeignPath(t *testing.T) {
	c, _ := catalogFixture(t)
	dir, err := trustedDirectory(c.root, c.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := c.holdFailedAdd(dir, "unconfigured"); err != nil {
		t.Fatal(err)
	}
	if err := c.holdFailedAdd(dir, "reenrolled"); err != nil {
		t.Fatal(err)
	}
	if err := c.clearFailedAdd(dir, "reenrolled"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.root, holdPrefix("unconfigured")+strings.Repeat("f", 32))
	if err := os.WriteFile(path, []byte("operator's data"), 0600); err != nil {
		t.Fatal(err)
	}
	holds, err := c.inactivePublisherHolds(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := holds["unconfigured"]; len(holds) != 1 || len(got) != 1 || got[0] != path {
		t.Fatalf("unexpected durable holds: %v", holds)
	}
	for _, action := range []string{"module.source-add", "module.catalog-install"} {
		raw, err := c.recoverCatalog(t.Context(), action)
		if err != nil || !strings.Contains(string(raw), path) || !strings.Contains(string(raw), `"publisher":"unconfigured"`) {
			t.Fatalf("recovery did not report held publisher and blocked path: %s, %v", raw, err)
		}
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	holds, err = c.inactivePublisherHolds(dir)
	if err != nil {
		t.Fatal(err)
	}
	if paths, found := holds["unconfigured"]; !found || len(paths) != 0 {
		t.Fatalf("missing hold after preserving the foreign file: %v", holds)
	}
}
