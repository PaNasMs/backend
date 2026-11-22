package modulelifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func servePendingRepository(t *testing.T, c *catalogService) map[string]any {
	t.Helper()
	const url = "https://pending.example.org/"
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"schemaVersion":1,"id":"pending","modules":[]}`)
	envelope, err := json.Marshal(signedBy{
		Algorithm: "Ed25519", Signer: "pending",
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw)),
	})
	if err != nil {
		t.Fatal(err)
	}
	original := c.download
	c.download = func(ctx context.Context, u string, limit int64, kind downloadKind) ([]byte, error) {
		switch u {
		case url + "catalog.json":
			return raw, nil
		case url + "catalog.sig":
			return envelope, nil
		case url + "keys/pending.pem":
			return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
		default:
			return original(ctx, u, limit, kind)
		}
	}
	return map[string]any{"url": url, "keyFingerprint": publicFingerprint(public)}
}

func TestFailedSourceAddPreservesLaterEditsAcrossRollbackRetry(t *testing.T) {
	for _, tc := range []struct {
		name         string
		matchingRows bool
		pemSource    string
	}{
		{"edited-source", false, "fixture"},
		{"matching-rows", true, "fixture"},
		{"matching-rows-confirmed-key", true, "pending"},
		{"matching-rows-without-key", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			const action = "module.source-add"
			c, serve := catalogFixture(t)
			params := servePendingRepository(t, &c)
			plan, err := c.planSource(ctx, action, params)
			if err != nil {
				t.Fatal(err)
			}
			manifest := fixtureManifest(t)
			manifest["signer"] = "fixture"
			if err := c.saveRegistry(Registry{"example": manifest}); err != nil {
				t.Fatal(err)
			}
			read := func(path string) []byte {
				t.Helper()
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			registryPath := filepath.Join(c.root, "registry.json")
			receipts := read(registryPath)
			before := read(c.config)
			stopped := errors.New("interrupted before config replacement")
			c.sourceBoundary = func(phase string) error {
				if phase == "key-written" {
					return stopped
				}
				return nil
			}
			if _, err := executePlannedSource(t, c, action, params); !errors.Is(err, stopped) {
				t.Fatalf("source-add returned %v", err)
			}
			if !bytes.Equal(read(c.config), before) {
				t.Fatal("failed add changed the configuration")
			}
			keyPath := filepath.Join(c.keys, "pending.pem")
			if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected no published key after failed add, stat returned %v", err)
			}

			rows := plan.after
			if !tc.matchingRows {
				rows = rows[:1]
				rows[0]["signers"] = []any{"fixture", "alternate"}
			}
			edited, err := json.MarshalIndent(rows, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(c.config, edited, 0600); err != nil {
				t.Fatal(err)
			}
			var independentPEM []byte
			switch tc.pemSource {
			case "fixture":
				independentPEM = read(filepath.Join(c.keys, "fixture.pem"))
			case "pending":
				independentPEM = plan.change.Keys["pending"]
				if len(independentPEM) == 0 {
					t.Fatal("missing planned publisher key")
				}
			}
			if independentPEM != nil {
				if err := os.WriteFile(keyPath, independentPEM, 0600); err != nil {
					t.Fatal(err)
				}
			}
			checkRollback := func(service catalogService) {
				t.Helper()
				if !bytes.Equal(read(c.config), edited) || !bytes.Equal(read(registryPath), receipts) {
					t.Fatal("rollback changed the edited configuration or installed receipts")
				}
				current, err := service.keyBytes("pending")
				if err != nil || !bytes.Equal(current, independentPEM) {
					t.Fatalf("publisher key changed during rollback: %v", err)
				}
				if key, err := service.activePublisherKey("pending"); err == nil || key != nil {
					t.Fatal("publisher of the failed add became active")
				}
			}

			syncErr := errors.New("rollback sync failed")
			c.sourceBoundary = func(phase string) error {
				if phase == "rollback-sync" {
					return syncErr
				}
				return nil
			}
			if _, err := c.recoverCatalog(ctx, action); !errors.Is(err, syncErr) {
				t.Fatalf("first rollback returned %v", err)
			}
			checkRollback(c)
			journal := filepath.Join(c.root, sourceIntent)
			if _, err := os.Stat(journal); err != nil {
				t.Fatalf("missing journal for rollback retry: %v", err)
			}

			restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
			if _, err := restarted.recoverCatalog(ctx, action); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected cleared journal after retry, stat returned %v", err)
			}
			serve("2.0.0", true)
			visibleCatalog(t, restarted, "2.0.0", tc.matchingRows)
			checkRollback(restarted)
		})
	}
}

func executePlannedSource(t *testing.T, c catalogService, action string, params map[string]any) (json.RawMessage, error) {
	t.Helper()
	fp := catalogPlanFingerprint(t, c, action, params)
	return c.executeCatalog(context.Background(), action, params, fp, nil, func() error { return nil })
}

func unconfiguredCatalogFixture(t *testing.T) (catalogService, func(string, bool), map[string]any, []byte) {
	t.Helper()
	c, serve := catalogFixture(t)
	raw, err := c.keyBytes("fixture")
	if err != nil {
		t.Fatal(err)
	}
	public, err := discoveryKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executePlannedSource(t, c, "module.source-remove", map[string]any{"target": "fixture"}); err != nil {
		t.Fatal(err)
	}
	serve("1.0.0", true)
	return c, serve, map[string]any{"url": "https://example.org/", "keyFingerprint": publicFingerprint(public)}, raw
}

func TestLegacySourceAddRecovery(t *testing.T) {
	for _, phase := range []string{"before-config", "after-config"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			c, serve, params, key := unconfiguredCatalogFixture(t)
			plan, err := c.planSource(ctx, "module.source-add", params)
			if err != nil {
				t.Fatal(err)
			}
			legacy, err := json.Marshal(map[string]any{
				"Add": true, "ID": "fixture", "Before": plan.change.Before, "After": plan.change.After,
				"Keys": map[string][]byte{"fixture": key},
			})
			if err != nil {
				t.Fatal(err)
			}
			journal := filepath.Join(c.root, sourceIntent)
			if err := os.WriteFile(journal, legacy, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(c.keys, "fixture.pem"), key, 0644); err != nil {
				t.Fatal(err)
			}
			if phase == "after-config" {
				rows, err := json.Marshal(plan.after)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(c.config, rows, 0600); err != nil {
					t.Fatal(err)
				}
			}

			restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
			if _, err := restarted.recoverCatalog(ctx, "module.source-add"); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected cleared legacy journal, stat returned %v", err)
			}
			configured, err := restarted.sources()
			if err != nil {
				t.Fatal(err)
			}
			current, err := restarted.keyBytes("fixture")
			if err != nil {
				t.Fatal(err)
			}
			if phase == "before-config" {
				if sourceState(configured) != plan.change.Before || current != nil {
					t.Fatal("legacy rollback retained the uncommitted source or key")
				}
				return
			}
			if sourceState(configured) != plan.change.After || !bytes.Equal(current, key) {
				t.Fatal("legacy recovery changed the committed source or key")
			}
			serve("2.0.0", true)
			visibleCatalog(t, restarted, "2.0.0", false)
		})
	}
}

func TestHeldPublisherReenrollmentAcrossRestart(t *testing.T) {
	ctx := context.Background()
	const add = "module.source-add"
	c, serve, params, key := unconfiguredCatalogFixture(t)
	plan, err := c.planSource(ctx, add, params)
	if err != nil {
		t.Fatal(err)
	}
	stopped := errors.New("interrupted source-add")
	interruptAt := func(boundary string) func(string) error {
		return func(phase string) error {
			if phase == boundary {
				return stopped
			}
			return nil
		}
	}
	c.sourceBoundary = interruptAt("key-written")
	if _, err := executePlannedSource(t, c, add, params); !errors.Is(err, stopped) {
		t.Fatalf("expected interrupted add, got %v", err)
	}
	rows, err := json.Marshal(plan.after)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.config, rows, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.keys, "fixture.pem"), key, 0644); err != nil {
		t.Fatal(err)
	}
	c.sourceBoundary = nil
	if _, err := c.recoverCatalog(ctx, add); err != nil {
		t.Fatal(err)
	}
	if active, err := c.activePublisherKey("fixture"); active != nil || err == nil {
		t.Fatal("independently configured publisher became active before re-enrollment")
	}
	if _, err := executePlannedSource(t, c, "module.source-remove", map[string]any{"target": "fixture"}); err != nil {
		t.Fatal(err)
	}
	c.sourceBoundary = interruptAt("config-written")
	outcome, err := executePlannedSource(t, c, add, params)
	if err != nil || !bytes.Contains(outcome, []byte(`"warnings"`)) {
		t.Fatalf("expected committed add with pending cleanup, got %s, %v", outcome, err)
	}
	if current, err := c.keyBytes("fixture"); err != nil || !bytes.Equal(current, key) {
		t.Fatalf("source removal or re-enrollment changed the independent PEM: %v", err)
	}
	if active, err := c.activePublisherKey("fixture"); err == nil || active != nil {
		t.Fatal("publisher became active before completing the new enrollment")
	}

	restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
	if _, err := restarted.recoverCatalog(ctx, add); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.root, sourceIntent)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected cleared journal after re-enrollment, stat returned %v", err)
	}
	current, err := restarted.keyBytes("fixture")
	if err != nil || !bytes.Equal(current, key) {
		t.Fatalf("committed add failed to preserve the reviewed PEM: %v", err)
	}
	active, err := restarted.activePublisherKey("fixture")
	if err != nil || publicFingerprint(active) != params["keyFingerprint"] {
		t.Fatalf("re-enrolled publisher was not active after restart: %v", err)
	}
	serve("2.0.0", true)
	visibleCatalog(t, restarted, "2.0.0", false)
}

func TestCommittedSourceAddRecoveryPreservesUnrelatedEdits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pemMode os.FileMode
	}{
		{"edited-other-source", 0},
		{"independent-pem", 0600},
		{"writable-confirmed-pem", 0666},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, serve := catalogFixture(t)
			params := servePendingRepository(t, &c)
			c.sourceBoundary = func(phase string) error {
				if phase == "config-written" {
					return errors.New("interrupted after config replacement")
				}
				return nil
			}
			result, err := executePlannedSource(t, c, "module.source-add", params)
			if err != nil || !bytes.Contains(result, []byte(`"warnings"`)) {
				t.Fatalf("expected committed add with pending cleanup, got %s, %v", result, err)
			}
			rows, err := c.sources()
			if err != nil {
				t.Fatal(err)
			}
			rows[0]["signers"] = []any{"fixture", "alternate"}
			delete(rows[len(rows)-1], "official")
			rows[len(rows)-1]["label"] = "operator annotation"
			edited, err := json.MarshalIndent(rows, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			replacement := filepath.Join(filepath.Dir(c.config), "edited.json")
			if err := os.WriteFile(replacement, edited, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, c.config); err != nil {
				t.Fatal(err)
			}
			var independent []byte
			keyPath := filepath.Join(c.keys, "pending.pem")
			if tc.pemMode != 0 {
				if tc.pemMode == 0666 {
					independent, err = c.download(context.Background(), "https://pending.example.org/keys/pending.pem", 8192, metadataDownload)
				} else {
					independent, err = c.keyBytes("fixture")
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(keyPath, independent, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(keyPath, tc.pemMode); err != nil {
					t.Fatal(err)
				}
			}

			restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
			serve("3.0.0", true)
			visibleCatalog(t, restarted, "3.0.0", tc.pemMode != 0)
			if current, err := os.ReadFile(c.config); err != nil || !bytes.Equal(current, edited) {
				t.Fatalf("recovery changed the independent config edit: %v", err)
			}
			if _, err := os.Stat(filepath.Join(c.root, sourceIntent)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected cleared journal after refresh, stat returned %v", err)
			}
			active, activeErr := restarted.activePublisherKey("pending")
			if tc.pemMode != 0 {
				if current, err := os.ReadFile(keyPath); err != nil || !bytes.Equal(current, independent) {
					t.Fatalf("recovery changed the independently installed PEM: %v", err)
				}
				stat, err := os.Stat(keyPath)
				if err != nil || stat.Mode().Perm() != tc.pemMode {
					t.Fatalf("recovery changed the independently installed PEM permissions: %v", err)
				}
				fenced, err := restarted.publisherFenced("pending")
				if err != nil || !fenced || active != nil || activeErr == nil {
					t.Fatalf("expected publisher of the independent PEM to remain inactive: %v", err)
				}
			} else if activeErr != nil || publicFingerprint(active) != params["keyFingerprint"] {
				t.Fatalf("committed publisher key was not installed after restart: %v", activeErr)
			}
		})
	}
}

func TestInterruptedReenrollmentHoldsPublisherAfterKeyReplacement(t *testing.T) {
	const action = "module.source-add"
	c, serve := catalogFixture(t)
	params := servePendingRepository(t, &c)
	plan, err := c.planSource(context.Background(), action, params)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(c.keys, "pending.pem")
	if err := os.WriteFile(keyPath, plan.change.Keys["pending"], 0600); err != nil {
		t.Fatal(err)
	}
	dir, err := trustedDirectory(c.root, c.owner)
	if err != nil {
		t.Fatal(err)
	}
	err = c.holdFailedAdd(dir, "pending")
	dir.Close()
	if err != nil {
		t.Fatal(err)
	}
	confirmed := false
	c.sourceBoundary = func(phase string) error {
		if phase == "publisher-confirmed" {
			confirmed = true
			return errors.New("interrupted after publisher confirmation")
		}
		return nil
	}
	result, err := executePlannedSource(t, c, action, params)
	if err != nil || !confirmed || !bytes.Contains(result, []byte(`"warnings"`)) {
		t.Fatalf("expected interruption after confirmation, got %s, %v", result, err)
	}
	if fenced, err := c.publisherFenced("pending"); err != nil || fenced {
		t.Fatalf("confirmation failed to release the enrolled publisher: %v", err)
	}
	independent, err := c.keyBytes("fixture")
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(c.keys, "replacement.pem")
	if err := os.WriteFile(replacement, independent, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, keyPath); err != nil {
		t.Fatal(err)
	}

	restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
	serve("4.0.0", true)
	visibleCatalog(t, restarted, "4.0.0", true)
	if current, err := restarted.keyBytes("pending"); err != nil || !bytes.Equal(current, independent) {
		t.Fatalf("recovery changed the independently replaced PEM: %v", err)
	}
	if fenced, err := restarted.publisherFenced("pending"); err != nil || !fenced {
		t.Fatalf("expected recovery to hold the publisher again: %v", err)
	}
	if _, err := os.Stat(filepath.Join(c.root, sourceIntent)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected recovery to retire the journal, stat returned %v", err)
	}
}

func TestFirstSourceConfigCommitSurvivesIndependentAtomicSave(t *testing.T) {
	c, serve, params, key := unconfiguredCatalogFixture(t)
	if err := os.Remove(c.config); err != nil {
		t.Fatal(err)
	}
	published := false
	c.sourceBoundary = func(phase string) error {
		if phase == "config-written" {
			published = true
			return errors.New("interrupted after publishing the first configuration")
		}
		return nil
	}
	result, err := executePlannedSource(t, c, "module.source-add", params)
	if err != nil || !published || !bytes.Contains(result, []byte(`"warnings"`)) {
		t.Fatalf("expected interruption after publishing the config, got %s, %v", result, err)
	}
	journal := filepath.Join(c.root, sourceIntent)
	raw, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var change sourceChange
	if err := json.Unmarshal(raw, &change); err != nil || change.AddDecision != "" {
		t.Fatalf("expected undecided journal after config publication: %v", err)
	}
	rows, err := c.sources()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0]["id"] != officialID || rows[1]["id"] != "fixture" {
		t.Fatalf("unexpected first source configuration: %v", rows)
	}
	edited, err := json.MarshalIndent(rows[1:], "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(filepath.Dir(c.config), "sources.new")
	if err := os.WriteFile(next, edited, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, c.config); err != nil {
		t.Fatal(err)
	}

	restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
	serve("5.0.0", true)
	visibleCatalog(t, restarted, "5.0.0", false)
	if active, err := restarted.activePublisherKey("fixture"); err != nil || publicFingerprint(active) != params["keyFingerprint"] {
		t.Fatalf("recovery did not activate the confirmed publisher: %v", err)
	}
	if current, err := restarted.keyBytes("fixture"); err != nil || !bytes.Equal(current, key) {
		t.Fatalf("recovery did not install the confirmed PEM: %v", err)
	}
	if current, err := os.ReadFile(c.config); err != nil || !bytes.Equal(current, edited) {
		t.Fatalf("recovery changed the independent configuration save: %v", err)
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected recovery to retire the journal, stat returned %v", err)
	}
}

func TestSourceAddRecoveryPublishesKeyOnce(t *testing.T) {
	for _, tc := range []struct {
		name, phase              string
		withdraw, supplyMatching bool
	}{
		{name: "committed", phase: "config-written"},
		{name: "preparing", phase: "key-preparing"},
		{name: "ready", phase: "key-ready"},
		{name: "before-rename", phase: "key-publishing"},
		{name: "existing-key-withdrawn", phase: "key-exists", withdraw: true, supplyMatching: true},
		{name: "renamed", phase: "key-published", withdraw: true},
		{name: "confirmed", phase: "publisher-confirmed", withdraw: true},
		{name: "existing-confirmed", phase: "publisher-confirmed", withdraw: true, supplyMatching: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, serve := catalogFixture(t)
			params := servePendingRepository(t, &c)
			manifest := fixtureManifest(t)
			manifest["signer"] = "fixture"
			if err := c.saveRegistry(Registry{"example": manifest}); err != nil {
				t.Fatal(err)
			}
			registryPath := filepath.Join(c.root, "registry.json")
			receipts, err := os.ReadFile(registryPath)
			if err != nil {
				t.Fatal(err)
			}
			interrupted := false
			c.sourceBoundary = func(stage string) error {
				if stage == "config-written" && tc.supplyMatching {
					raw, err := c.download(context.Background(), "https://pending.example.org/keys/pending.pem", 8192, metadataDownload)
					if err != nil {
						return err
					}
					return os.WriteFile(filepath.Join(c.keys, "pending.pem"), raw, 0600)
				}
				if stage == tc.phase {
					interrupted = true
					return errors.New("interrupted source add")
				}
				return nil
			}
			outcome, err := executePlannedSource(t, c, "module.source-add", params)
			if err != nil || !interrupted || !bytes.Contains(outcome, []byte(`"warnings"`)) {
				t.Fatalf("expected interrupted publication, got %s, %v", outcome, err)
			}
			configured, err := os.ReadFile(c.config)
			if err != nil {
				t.Fatal(err)
			}
			if tc.withdraw {
				raw, err := os.ReadFile(filepath.Join(c.keys, "pending.pem"))
				if err != nil {
					t.Fatal(err)
				}
				key, err := discoveryKey(raw)
				if err != nil || publicFingerprint(key) != params["keyFingerprint"] {
					t.Fatalf("reviewed key was not installed: %v", err)
				}
				if err := os.Remove(filepath.Join(c.keys, "pending.pem")); err != nil {
					t.Fatal(err)
				}
			} else if current, err := c.keyBytes("pending"); err != nil || current != nil {
				t.Fatalf("unexpected key before publication: %v", err)
			}

			restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
			serve("6.0.0", true)
			wantHeld := tc.withdraw
			visibleCatalog(t, restarted, "6.0.0", wantHeld)
			if held, err := restarted.publisherFenced("pending"); err != nil || held != wantHeld {
				t.Fatalf("expected held=%v after recovery, got %v, %v", wantHeld, held, err)
			}
			if wantHeld {
				if current, err := restarted.keyBytes("pending"); err != nil || current != nil {
					t.Fatalf("recovery recreated a missing PEM: %v", err)
				}
			} else if key, err := restarted.activePublisherKey("pending"); err != nil || publicFingerprint(key) != params["keyFingerprint"] {
				t.Fatalf("recovery failed to publish the reviewed key: %v", err)
			}
			if current, err := os.ReadFile(registryPath); err != nil || !bytes.Equal(current, receipts) {
				t.Fatalf("recovery changed installed receipts: %v", err)
			}
			if current, err := os.ReadFile(c.config); err != nil || !bytes.Equal(current, configured) {
				t.Fatalf("recovery changed configured sources: %v", err)
			}
			if _, err := os.Stat(filepath.Join(c.root, sourceIntent)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected retired journal, stat returned %v", err)
			}
			drafts, err := os.ReadDir(filepath.Join(c.keys, sourceAddStageRoot))
			if err != nil || len(drafts) != 0 {
				t.Fatalf("expected no remaining private key drafts, got %v, %v", drafts, err)
			}
		})
	}
}

func TestSourceAddReportsInactivePublisherAfterKeyConflict(t *testing.T) {
	c, _ := catalogFixture(t)
	params := servePendingRepository(t, &c)
	independent, err := c.keyBytes("fixture")
	if err != nil {
		t.Fatal(err)
	}
	c.sourceBoundary = func(phase string) error {
		if phase == "config-written" {
			return os.WriteFile(filepath.Join(c.keys, "pending.pem"), independent, 0600)
		}
		return nil
	}
	raw, err := executePlannedSource(t, c, "module.source-add", params)
	if err != nil {
		t.Fatal(err)
	}
	var result struct{ Warnings []string }
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Warnings) != 1 || result.Warnings[0] != errSourceAddFenced.Error() {
		t.Fatalf("expected publisher re-enrollment warning, got %s, %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(c.root, sourceIntent)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected completed cleanup after conflict, stat returned %v", err)
	}
}

func TestCommittedSourceAddAcceptsMatchingLocalPEMHeaders(t *testing.T) {
	c, serve := catalogFixture(t)
	params := servePendingRepository(t, &c)
	c.sourceBoundary = func(stage string) error {
		if stage == "config-written" {
			return errors.New("interrupted after config replacement")
		}
		return nil
	}
	outcome, err := executePlannedSource(t, c, "module.source-add", params)
	if err != nil || !bytes.Contains(outcome, []byte(`"warnings"`)) {
		t.Fatalf("expected a committed add with pending recovery: %s, %v", outcome, err)
	}
	raw, err := c.download(context.Background(), "https://pending.example.org/keys/pending.pem", 8192, metadataDownload)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	block.Headers = map[string]string{"Comment": "Local publisher key"}
	local := pem.EncodeToMemory(block)
	path := filepath.Join(c.keys, "pending.pem")
	if err := os.WriteFile(path, local, 0600); err != nil {
		t.Fatal(err)
	}

	restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
	serve("7.0.0", true)
	visibleCatalog(t, restarted, "7.0.0", false)
	if current, err := os.ReadFile(path); err != nil || !bytes.Equal(current, local) {
		t.Fatalf("recovery changed the local PEM representation: %v", err)
	}
	if key, err := restarted.activePublisherKey("pending"); err != nil || publicFingerprint(key) != params["keyFingerprint"] {
		t.Fatalf("expected the matching local key to be active: %v", err)
	}
}

func TestExplicitSourceRecoveryReportsOccupiedKeyStage(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			c, serve := catalogFixture(t)
			params := servePendingRepository(t, &c)
			path := filepath.Join(c.keys, sourceAddStageRoot)
			contents := []byte("local notes")
			notes := path
			if kind == "directory" {
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
				notes = filepath.Join(path, "notes")
			}
			if err := os.WriteFile(notes, contents, 0600); err != nil {
				t.Fatal(err)
			}
			c.sourceBoundary = func(stage string) error {
				if stage == "config-written" {
					return errors.New("interrupted after config replacement")
				}
				return nil
			}
			outcome, err := executePlannedSource(t, c, "module.source-add", params)
			if err != nil || !bytes.Contains(outcome, []byte(`"warnings"`)) {
				t.Fatalf("expected a committed add with pending recovery: %s, %v", outcome, err)
			}

			restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
			for _, action := range []string{"module.catalog-install", "module.source-add"} {
				raw, err := restarted.recoverCatalog(context.Background(), action)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(raw, []byte(path)) || !bytes.Contains(raw, []byte("move aside")) || !bytes.Contains(raw, []byte(`"publisher":"pending"`)) {
					t.Fatalf("expected an actionable recovery report naming the inactive publisher: %s", raw)
				}
				if _, err := os.Stat(filepath.Join(c.root, sourceIntent)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("expected a retired journal, stat returned %v", err)
				}
			}
			if current, err := os.ReadFile(notes); err != nil || !bytes.Equal(current, contents) {
				t.Fatalf("recovery changed the operator file: %v", err)
			}
			if key, err := restarted.activePublisherKey("pending"); key != nil || err == nil {
				t.Fatal("publisher with a blocked key stage became active")
			}
			serve("8.0.0", true)
			visibleCatalog(t, restarted, "8.0.0", true)
			catalogPlanFingerprint(t, restarted, "module.source-remove", map[string]any{"target": "fixture"})
			if kind == "directory" {
				if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0755 {
					t.Fatalf("recovery changed the operator directory permissions: %v", err)
				}
			}
			if err := os.Rename(path, path+".saved"); err != nil {
				t.Fatal(err)
			}
			if _, err := executePlannedSource(t, restarted, "module.source-remove", map[string]any{"target": "pending"}); err != nil {
				t.Fatal(err)
			}
			result, err := executePlannedSource(t, restarted, "module.source-add", params)
			if err != nil || bytes.Contains(result, []byte(`"warnings"`)) {
				t.Fatalf("re-enrollment after moving the conflict failed: %s, %v", result, err)
			}
			if key, err := restarted.activePublisherKey("pending"); err != nil || publicFingerprint(key) != params["keyFingerprint"] {
				t.Fatalf("publisher did not recover after following the report: %v", err)
			}
		})
	}
}

func TestSourceKeyPublicationAfterHelperExit(t *testing.T) {
	const exited = 74
	const action = "module.source-add"
	const url = "https://pending.example.org/"
	if cut := os.Getenv("PANASMS_TEST_KEY_HELPER_EXIT"); cut != "" {
		var replies map[string][]byte
		if err := json.Unmarshal([]byte(os.Getenv("PANASMS_TEST_KEY_REPLIES")), &replies); err != nil {
			t.Fatal(err)
		}
		root := os.Getenv("PANASMS_TEST_KEY_ROOT")
		c := catalogService{
			lifecycle: lifecycle{store: store{root: root, owner: uint32(os.Geteuid())}, keys: os.Getenv("PANASMS_TEST_KEY_DIR")},
			config:    filepath.Join(root, "sources.json"),
			download: func(_ context.Context, u string, _ int64, _ downloadKind) ([]byte, error) {
				return replies[u], nil
			},
		}
		raw := replies[url+"keys/pending.pem"]
		key, err := discoveryKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		c.sourceBoundary = func(phase string) error {
			if phase == "config-written" && cut != "key-publishing" {
				return os.WriteFile(filepath.Join(c.keys, "pending.pem"), raw, 0600)
			}
			if phase == "key-link" {
				switch cut {
				case "immutable", "immutable-withdrawn":
					return unix.EPERM
				case "mounted", "mounted-withdrawn":
					return unix.EXDEV
				}
			}
			if phase == cut || phase == "key-exists" && cut != "key-publishing" {
				os.Exit(exited)
			}
			return nil
		}
		_, err = executePlannedSource(t, c, action, map[string]any{"url": url, "keyFingerprint": publicFingerprint(key)})
		t.Fatalf("child did not stop at %s: %v", cut, err)
	}

	for _, cut := range []string{"key-publishing", "key-exists", "immutable", "immutable-withdrawn", "mounted", "mounted-withdrawn"} {
		t.Run(cut, func(t *testing.T) {
			c, serve := catalogFixture(t)
			params := servePendingRepository(t, &c)
			replies := map[string][]byte{}
			for _, path := range []string{"catalog.json", "catalog.sig", "keys/pending.pem"} {
				raw, err := c.download(t.Context(), url+path, maxCatalog, metadataDownload)
				if err != nil {
					t.Fatal(err)
				}
				replies[url+path] = raw
			}
			raw, err := json.Marshal(replies)
			if err != nil {
				t.Fatal(err)
			}
			child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSourceKeyPublicationAfterHelperExit$")
			child.Env = append(os.Environ(), "PANASMS_TEST_KEY_HELPER_EXIT="+cut, "PANASMS_TEST_KEY_ROOT="+c.root,
				"PANASMS_TEST_KEY_DIR="+c.keys, "PANASMS_TEST_KEY_REPLIES="+string(raw))
			out, err := child.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != exited {
				t.Fatalf("expected helper exit at %s: %v, %s", cut, err, out)
			}
			path := filepath.Join(c.keys, "pending.pem")
			withdrawn := cut == "key-exists" || cut == "immutable-withdrawn" || cut == "mounted-withdrawn"
			var supplied os.FileInfo
			if cut != "key-publishing" {
				supplied, err = os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if expected := replies[url+"keys/pending.pem"]; len(expected) == 0 {
					t.Fatal("missing reviewed publisher PEM")
				} else if current, err := os.ReadFile(path); err != nil || !bytes.Equal(current, expected) {
					t.Fatalf("existing publisher key changed before recovery: %v", err)
				}
			}
			if withdrawn {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else if cut == "key-publishing" {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("expected an unpublished key, stat returned %v", err)
				}
			}
			serve("9.0.0", true)
			visibleCatalog(t, c, "9.0.0", withdrawn)
			if withdrawn {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("recovery recreated a withdrawn key: %v", err)
				}
				if held, err := c.publisherFenced("pending"); err != nil || !held {
					t.Fatalf("expected publisher to remain inactive: %v", err)
				}
			} else if key, err := c.activePublisherKey("pending"); err != nil || publicFingerprint(key) != params["keyFingerprint"] {
				t.Fatalf("recovery failed to publish the reviewed key: %v", err)
			}
			if supplied != nil && !withdrawn {
				current, err := os.Stat(path)
				if err != nil || !os.SameFile(supplied, current) || supplied.Mode() != current.Mode() {
					t.Fatalf("recovery replaced or changed the existing PEM: %v", err)
				}
			}
			files, err := os.ReadDir(filepath.Join(c.keys, sourceAddStageRoot))
			if err != nil || len(files) != 0 {
				t.Fatalf("private key stage retained files after recovery: %v, %v", files, err)
			}
		})
	}
}

func TestKeyObservationReservesOnlyVacantName(t *testing.T) {
	c, _ := catalogFixture(t)
	keys, err := trustedDirectory(c.keys, c.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	const id = "a529fc77016d4d65b41463edb4ffaf72"
	private := filepath.Join(c.keys, sourceAddStageRoot)
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(private, id+".seen")
	const contents = "existing local file"
	if err := os.WriteFile(foreign, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	stage := sourceAddStage{ID: id, Owner: c.owner}
	stage, err = stage.writeDraft(keys, []byte("test draft"), 0644, func(sourceAddStage) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.reserveKeyObservation(keys); !errors.Is(err, errSourceAddFenced) {
		t.Fatalf("expected occupied observation name to stop enrollment: %v", err)
	}
	if err := stage.releaseKeyObservation(keys); err != nil {
		t.Fatal(err)
	}
	if err := stage.cleanup(keys); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(foreign); err != nil || string(raw) != contents {
		t.Fatalf("cleanup changed a pre-existing entry: %v", err)
	}
}

func TestKeyObservationPreservesPublisherSymlink(t *testing.T) {
	c, serve := catalogFixture(t)
	params := servePendingRepository(t, &c)
	path := filepath.Join(c.keys, "pending.pem")
	c.sourceBoundary = func(stage string) error {
		if stage == "config-written" {
			return os.Symlink("fixture.pem", path)
		}
		return nil
	}
	outcome, err := executePlannedSource(t, c, "module.source-add", params)
	if err != nil || !bytes.Contains(outcome, []byte(errSourceAddFenced.Error())) {
		t.Fatalf("expected inactive publisher warning: %s, %v", outcome, err)
	}
	if target, err := os.Readlink(path); err != nil || target != "fixture.pem" {
		t.Fatalf("publisher symlink changed: %q, %v", target, err)
	}
	serve("10.0.0", true)
	visibleCatalog(t, c, "10.0.0", true)
}

func TestCrossMountKeyPublicationLeavesUnrelatedCatalogAvailable(t *testing.T) {
	c, serve := catalogFixture(t)
	params := servePendingRepository(t, &c)
	blocked := false
	c.sourceBoundary = func(phase string) error {
		if phase == "key-rename" {
			blocked = true
			return unix.EXDEV
		}
		return nil
	}
	raw, err := executePlannedSource(t, c, "module.source-add", params)
	if err != nil || !blocked || !bytes.Contains(raw, []byte(errSourceAddFenced.Error())) {
		t.Fatalf("expected terminal publisher warning, got %s, %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(c.root, sourceIntent)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected the cross-mount conflict to retire the source journal: %v", err)
	}
	restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
	if held, err := restarted.publisherFenced("pending"); err != nil || !held {
		t.Fatalf("expected only the affected publisher to remain inactive: %v", err)
	}
	if key, err := restarted.keyBytes("pending"); err != nil || key != nil {
		t.Fatalf("unexpected public key after failed rename: %v", err)
	}
	serve("11.0.0", true)
	visibleCatalog(t, restarted, "11.0.0", true)
	drafts, err := os.ReadDir(filepath.Join(c.keys, sourceAddStageRoot))
	if err != nil || len(drafts) != 0 {
		t.Fatalf("expected retired private key draft: %v, %v", drafts, err)
	}
}
