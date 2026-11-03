package modulelifecycle

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransactionEffectiveIdentityIgnoresSignedInstallationAndEnabledFields(t *testing.T) {
	s := fixtureLifecycle(t)
	forged := strings.Repeat("b", 32)
	raw, key := archiveFixture(t, func(m Manifest, _ *[]archiveEntry) {
		m["installation"] = forged
		m["enabled"] = false
		m["future"] = map[string]any{"counter": json.Number("9007199254740993")}
	}, false)
	token := putUploadFixture(t, s, raw, key)
	plan, err := s.prepare(context.Background(), "module.install", map[string]any{"upload": token}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer plan.archive.Close()
	fresh, err := s.transactionFor("module.install", plan)
	if err != nil {
		t.Fatal(err)
	}
	freshID := text(fresh.After["example"], "installation")
	if !uploadToken.MatchString(freshID) || freshID == forged || fresh.After["example"]["enabled"] != true {
		t.Fatal(fresh.After)
	}
	if fresh.After["example"]["future"].(map[string]any)["counter"] != json.Number("9007199254740993") {
		t.Fatal("signed future metadata lost")
	}
	old := fixtureManifest(t)
	old["version"] = "0.9.0"
	old["signer"] = "fixture"
	old["enabled"] = false
	old["installation"] = freshID
	if err = s.saveRegistry(Registry{"example": old}); err != nil {
		t.Fatal(err)
	}
	update, err := s.prepare(context.Background(), "module.install", map[string]any{"upload": token}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer update.archive.Close()
	updated, err := s.transactionFor("module.install", update)
	if err != nil {
		t.Fatal(err)
	}
	if text(updated.After["example"], "installation") != freshID || updated.After["example"]["enabled"] != false {
		t.Fatal("upgrade changed identity/disabled state", updated.After)
	}
	updated.After["example"]["future"].(map[string]any)["counter"] = "changed"
	if plan.available["example"]["future"].(map[string]any)["counter"] != json.Number("9007199254740993") {
		t.Fatal("transaction mutated verified archive metadata")
	}
	plan.installed = Registry{}
	reinstalled, err := s.transactionFor("module.install", plan)
	if err != nil {
		t.Fatal(err)
	}
	if text(reinstalled.After["example"], "installation") == freshID {
		t.Fatal("new installation reused removed identity")
	}
}

func TestBeginDurablyWritesBeforeStagingAndPreservesConflictingDirectory(t *testing.T) {
	s := fixtureLifecycle(t)
	token := uploadFixture(t, s)
	plan, err := s.prepare(context.Background(), "module.install", map[string]any{"upload": token}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer plan.archive.Close()
	state, err := s.begin("module.install", plan)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := s.loadTransaction()
	if err != nil || loaded.Phase != "staging" || len(loaded.Before) != 0 || loaded.After["example"] == nil || loaded.Payloads["example"].Staged.Exists {
		t.Fatal(loaded, err)
	}
	info, err := os.Stat(filepath.Join(s.root, ".transaction"))
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal(info, err)
	}
	info, err = os.Stat(filepath.Join(s.root, ".transaction/journal.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, err)
	}
	before, err := os.ReadFile(filepath.Join(s.root, ".transaction/journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	conflict, err := s.begin("module.install", plan)
	if err == nil || conflict != nil {
		t.Fatal("conflicting transaction adopted", conflict, err)
	}
	after, err := os.ReadFile(filepath.Join(s.root, ".transaction/journal.json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("conflicting evidence overwritten", err)
	}
	r := recovery{store: s.store, units: s.units, mounts: s.mounts, run: s.run, health: s.health}
	if err = r.restore(context.Background(), state, nil); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityCorruptionAndUnreceiptedPayloadAreNeverAdopted(t *testing.T) {
	for _, value := range []any{"wrong", true, json.Number("123"), map[string]any{"nonce": "unexpected"}} {
		if _, err := installationID(Manifest{"installation": value}); err == nil {
			t.Fatal("corrupt installation identity accepted", value)
		}
	}
	s := fixtureLifecycle(t)
	token := uploadFixture(t, s)
	if err := os.Mkdir(filepath.Join(s.root, "example"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.root, "example/foreign-data"), []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.prepare(context.Background(), "module.install", map[string]any{"upload": token}, "alice"); err == nil {
		t.Fatal("unregistered payload adopted for deletion")
	}
	if raw, err := os.ReadFile(filepath.Join(s.root, "example/foreign-data")); err != nil || string(raw) != "preserved" {
		t.Fatal(string(raw), err)
	}
}
