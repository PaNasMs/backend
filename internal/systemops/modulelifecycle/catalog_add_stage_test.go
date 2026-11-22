package modulelifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceAddUnderSetgidConfigParent(t *testing.T) {
	c, _ := catalogFixture(t)
	parent := filepath.Join(c.root, "etc")
	if err := os.Mkdir(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, os.ModeSetgid|0755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(parent, filepath.Base(c.config))
	if err := os.Rename(c.config, config); err != nil {
		t.Fatal(err)
	}
	c.config = config
	params := servePendingRepository(t, &c)
	if _, err := executePlannedSource(t, c, "module.source-add", params); err != nil {
		t.Fatal(err)
	}
	key, err := c.activePublisherKey("pending")
	if err != nil || publicFingerprint(key) != params["keyFingerprint"] {
		t.Fatalf("expected confirmed publisher: %v", err)
	}
	if _, err := os.Stat(filepath.Join(c.root, sourceIntent)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("enrollment retained journal: %v", err)
	}
	info, err := os.Stat(parent)
	if err != nil || info.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("setgid config parent changed: %v", err)
	}
}

func interruptedSourceStage(t *testing.T, c catalogService, params map[string]any, cut string) sourceChange {
	t.Helper()
	stop := errors.New("interrupted source staging")
	c.sourceBoundary = func(phase string) error {
		if phase == cut {
			return stop
		}
		return nil
	}
	if _, err := executePlannedSource(t, c, "module.source-add", params); !errors.Is(err, stop) {
		t.Fatalf("expected interruption at %s, got %v", cut, err)
	}
	raw, err := os.ReadFile(filepath.Join(c.root, sourceIntent))
	if err != nil {
		t.Fatal(err)
	}
	var change sourceChange
	if err := json.Unmarshal(raw, &change); err != nil || change.Stage == nil || change.AddID == "" {
		t.Fatalf("missing staged enrollment in journal: %v", err)
	}
	return change
}

func TestSourceAddRecoveryAfterDraftLink(t *testing.T) {
	c, _ := catalogFixture(t)
	params := servePendingRepository(t, &c)
	before, err := os.ReadFile(c.config)
	if err != nil {
		t.Fatal(err)
	}
	change := interruptedSourceStage(t, c, params, "draft-linked")
	if change.AddDecision != "preparing" {
		t.Fatalf("draft link occurred after journal advanced to %q", change.AddDecision)
	}
	slot := filepath.Join(filepath.Dir(c.config), ".panasms-source-staging", change.AddID)
	if _, err := os.Stat(slot); err != nil {
		t.Fatalf("missing linked draft at interruption: %v", err)
	}
	// The operator installs the reviewed PEM after the first helper stops.
	key := change.Keys["pending"]
	keyPath := filepath.Join(c.keys, "pending.pem")
	if len(key) == 0 {
		t.Fatal("expected staged publisher PEM")
	}
	if err := os.WriteFile(keyPath, key, 0644); err != nil {
		t.Fatal(err)
	}
	restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
	if _, err := restarted.recoverCatalog(t.Context(), "module.source-add"); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.activePublisherKey("pending"); err == nil {
		t.Fatal("linked draft activated the publisher")
	}
	if got, err := os.ReadFile(keyPath); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("operator PEM changed: %v", err)
	}
	if got, err := os.ReadFile(c.config); err != nil || !bytes.Equal(got, before) {
		t.Fatalf("live config changed: %v", err)
	}
	for _, path := range []string{slot, filepath.Join(c.root, sourceIntent)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rollback retained %s: %v", filepath.Base(path), err)
		}
	}
}

func TestSourceAddDraftIdentityTakesPriorityOverReusedInode(t *testing.T) {
	c, _ := catalogFixture(t)
	params := servePendingRepository(t, &c)
	change := interruptedSourceStage(t, c, params, "key-written")
	stage := *change.Stage
	if stage.Before.Inode == 0 || stage.After.Inode == 0 || stage.Before.Digest == stage.After.Digest {
		t.Fatal("expected distinct recorded config and draft contents")
	}
	// Model sequential inode reuse in the journal while the private slot still
	// contains the original draft. No writer touches the slot during recovery.
	stage.Before.Inode = stage.After.Inode
	config, err := trustedDirectory(filepath.Dir(c.config), c.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	committed, err := stage.committed(config)
	if err != nil || committed {
		t.Fatalf("draft reported as committed after inode reuse: committed=%v err=%v", committed, err)
	}
}
