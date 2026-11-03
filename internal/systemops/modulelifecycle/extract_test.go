package modulelifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"panasms.local/backend/internal/systemops"
)

func extractionFixture(t *testing.T) (lifecycle, *prepared, *transaction) {
	t.Helper()
	s := fixtureLifecycle(t)
	token := uploadFixture(t, s)
	plan, err := s.prepare(context.Background(), "module.install", map[string]any{"upload": token}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { plan.archive.Close() })
	if err = os.Mkdir(filepath.Join(s.root, ".transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	state := &transaction{Before: Registry{}, After: Registry{"example": plan.available["example"]}, Affected: plan.order, Schema: 1, Phase: "staging", Units: plan.units, Candidates: map[string]fileSnapshot{"example": {}}, Payloads: plan.payloads}
	if err = s.saveTransaction(state); err != nil {
		t.Fatal(err)
	}
	return s, plan, state
}

func TestExtractionWritesOnlySignedStagedPayloadAndDurableIdentity(t *testing.T) {
	s, plan, state := extractionFixture(t)
	if err := s.extract(context.Background(), plan, state, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.root, ".transaction/.new/example/ui/index.js")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != plan.available["example"]["files"].(map[string]any)["ui/index.js"] {
		t.Fatal("unsigned staged bytes")
	}
	if _, err = os.Stat(filepath.Join(s.root, "example")); !os.IsNotExist(err) {
		t.Fatal("extraction changed installed payload", err)
	}
	if _, err = os.Stat(filepath.Join(s.root, ".transaction/old-example")); !os.IsNotExist(err) {
		t.Fatal("extraction created backup alias", err)
	}
	loaded, err := s.loadTransaction()
	if err != nil || !loaded.Payloads["example"].Staged.Exists || loaded.Payloads["example"].Staged != state.Payloads["example"].Staged {
		t.Fatal(loaded, err)
	}
	for _, name := range []string{"example", "example/ui"} {
		info, err := os.Stat(filepath.Join(s.root, ".transaction/.new", name))
		if err != nil || info.Mode().Perm() != 0755 {
			t.Fatal(name, info, err)
		}
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Fatal(info.Mode())
	}
}

func TestCanceledExtractionRetainsJournalWithoutPublishingAndRecoversStagingOnly(t *testing.T) {
	s, plan, state := extractionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.extract(ctx, plan, state, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.root, ".transaction/journal.json")); err != nil {
		t.Fatal("cancel discarded evidence", err)
	}
	r := recovery{store: s.store, units: s.units, mounts: s.mounts, run: s.run, health: s.health}
	if err := r.restore(context.Background(), state, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.root, ".transaction")); !os.IsNotExist(err) {
		t.Fatal("staging cleanup incomplete", err)
	}
	registry, err := s.registry()
	if err != nil || len(registry) != 0 {
		t.Fatal(registry, err)
	}
}

func TestExtractedFileChecksDigestAndServerPermissions(t *testing.T) {
	s := fixtureStore(t)
	dir, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	payload := []byte("native executable fixture")
	hash := sha256.Sum256(payload)
	digest := hex.EncodeToString(hash[:])
	if err = extractFile(context.Background(), dir, "server", bytes.NewReader(payload), uint64(len(payload)), digest, 0755, s.owner, nil); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(s.root, "server"))
	if info.Mode().Perm() != 0755 {
		t.Fatal(info.Mode())
	}
	if err = extractFile(context.Background(), dir, "changed", bytes.NewReader([]byte("changed")), uint64(len(payload)), digest, 0644, s.owner, nil); err == nil {
		t.Fatal("changed archive payload accepted")
	}
	if err = extractFile(context.Background(), dir, "server", bytes.NewReader(payload), uint64(len(payload)), digest, 0755, s.owner, nil); err == nil {
		t.Fatal("existing staged executable replaced")
	}
}

func TestLegacyStagingBackupNameCollisionPreservesEvidenceBeforeCommands(t *testing.T) {
	r, state := recoveryFixture(t, true)
	state.Schema = 0
	state.Phase = ""
	state.After = nil
	state.Candidates = nil
	state.Units = nil
	state.Payloads = nil
	state.Affected = append(state.Affected, "old-app")
	state.Before["old-app"] = Manifest{"id": "old-app", "enabled": false}
	if err := r.saveTransaction(state); err != nil {
		t.Fatal(err)
	}
	r.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
		t.Fatal("ambiguous legacy recovery executed a command")
		return nil, nil
	}
	if err := r.restore(context.Background(), state, nil); err == nil {
		t.Fatal("ambiguous staging interpreted as an old payload")
	}
	if _, err := os.Stat(filepath.Join(r.root, ".transaction/old-app/payload")); err != nil {
		t.Fatal("ambiguous evidence removed", err)
	}
}

func TestSignedOldPrefixModuleUsesDisjointNewNamespace(t *testing.T) {
	s := fixtureLifecycle(t)
	raw, key := archiveFixture(t, func(m Manifest, entries *[]archiveEntry) {
		m["id"] = "old-example"
		(*entries)[0].data = []byte(`{"root":"old-example"}`)
		(*entries)[1].name = "modules/old-example/ui/index.js"
	}, false)
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(s.keys, "fixture.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 32)
	if err = os.WriteFile(filepath.Join(s.uploads, "alice-"+token+".zip"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := s.prepare(context.Background(), "module.install", map[string]any{"upload": token}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer plan.archive.Close()
	if err = os.Mkdir(filepath.Join(s.root, ".transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	state := &transaction{Before: Registry{}, After: Registry{"old-example": plan.available["old-example"]}, Affected: plan.order, Schema: 1, Phase: "staging", Units: plan.units, Candidates: map[string]fileSnapshot{"old-example": {}}, Payloads: plan.payloads}
	if err = s.saveTransaction(state); err != nil {
		t.Fatal(err)
	}
	if err = s.extract(context.Background(), plan, state, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(s.root, ".transaction/.new/old-example/ui/index.js")); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(s.root, ".transaction/old-example")); !os.IsNotExist(err) {
		t.Fatal("staged module overlaps legacy backup slot", err)
	}
}
