package modulelifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
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

func TestSourceAddRecoveryAfterHelperExit(t *testing.T) {
	const add = "module.source-add"
	const stopped = 73
	type operatorFiles struct {
		Rows []map[string]any
		PEM  []byte
	}
	if cut := os.Getenv("PANASMS_TEST_SOURCE_ADD_EXIT"); cut != "" {
		root := os.Getenv("PANASMS_TEST_SOURCE_ROOT")
		c := catalogService{
			lifecycle: lifecycle{store: store{root: root, owner: uint32(os.Geteuid())}, keys: os.Getenv("PANASMS_TEST_SOURCE_KEYS")},
			config:    filepath.Join(root, "sources.json"),
		}
		params := servePendingRepository(t, &c)
		plan, err := c.planSource(t.Context(), add, params)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(operatorFiles{plan.after, plan.change.Keys["pending"]}); err != nil {
			t.Fatal(err)
		}
		c.sourceBoundary = func(phase string) error {
			if phase == cut {
				os.Exit(stopped)
			}
			return nil
		}
		_, err = executePlannedSource(t, c, add, params)
		t.Fatalf("helper did not exit at %s: %v", cut, err)
	}

	for _, cut := range []string{"key-written", "enrollment-reserved"} {
		t.Run(cut, func(t *testing.T) {
			c, serve := catalogFixture(t)
			manifest := fixtureManifest(t)
			manifest["signer"] = "fixture"
			if err := c.saveRegistry(Registry{"example": manifest}); err != nil {
				t.Fatal(err)
			}
			registry := filepath.Join(c.root, "registry.json")
			receipts, err := os.ReadFile(registry)
			if err != nil {
				t.Fatal(err)
			}
			serve("1.0.0", true)
			visibleCatalog(t, c, "1.0.0", false)
			before, err := os.ReadFile(c.config)
			if err != nil {
				t.Fatal(err)
			}
			child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSourceAddRecoveryAfterHelperExit$")
			child.Env = append(os.Environ(), "PANASMS_TEST_SOURCE_ADD_EXIT="+cut,
				"PANASMS_TEST_SOURCE_ROOT="+c.root, "PANASMS_TEST_SOURCE_KEYS="+c.keys)
			var diagnostics bytes.Buffer
			child.Stderr = &diagnostics
			out, err := child.Output()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != stopped {
				t.Fatalf("expected helper to exit at %s: %v\n%s%s", cut, err, out, diagnostics.Bytes())
			}
			if got, err := os.ReadFile(c.config); err != nil || !bytes.Equal(got, before) {
				t.Fatalf("helper published config before %s: %v", cut, err)
			}
			if cut == "enrollment-reserved" {
				if _, err := os.Readlink(filepath.Join(c.root, sourceAddClaim)); err != nil {
					t.Fatalf("missing reservation when helper exited: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(c.root, sourceIntent)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("journal already present at reservation: %v", err)
				}
			}
			var files operatorFiles
			if err := json.Unmarshal(out, &files); err != nil || len(files.PEM) == 0 || len(files.Rows) != 2 {
				t.Fatalf("missing intended repository files: %v", err)
			}
			// After the helper exits, an operator saves even the exact planned rows
			// and independently supplies the matching publisher key.
			edited, err := json.MarshalIndent(files.Rows, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(c.config+".operator", edited, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(c.config+".operator", c.config); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(c.keys, "pending.pem")
			if err := os.WriteFile(key, files.PEM, 0644); err != nil {
				t.Fatal(err)
			}
			restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
			if _, err := restarted.recoverCatalog(t.Context(), add); err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.activePublisherKey("pending"); err == nil {
				t.Fatal("interrupted helper authorized the operator's key")
			}
			for _, name := range []string{sourceAddClaim, sourceIntent} {
				if _, err := os.Lstat(filepath.Join(c.root, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("recovery retained %s: %v", name, err)
				}
			}
			serve("2.0.0", true)
			visibleCatalog(t, restarted, "2.0.0", true)
			for path, want := range map[string][]byte{c.config: edited, key: files.PEM, registry: receipts} {
				if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
					t.Fatalf("recovery changed %s: %v", filepath.Base(path), err)
				}
			}
		})
	}
}
