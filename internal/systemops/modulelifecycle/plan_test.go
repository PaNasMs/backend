package modulelifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"panasms.local/backend/internal/systemops"
)

func fixtureLifecycle(t *testing.T) lifecycle {
	t.Helper()
	return lifecycle{store: fixtureStore(t), core: "0.2.34", architecture: "amd64", units: fixtureStore(t).root, uploads: fixtureStore(t).root, keys: fixtureStore(t).root, compare: compareDebian, run: func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
		t.Fatal("unexpected package or service command")
		return nil, nil
	}, health: func(context.Context, string) (map[string]any, error) {
		t.Fatal("unexpected module health query")
		return nil, nil
	}, mounts: func() ([]string, error) { return []string{}, nil }}
}

func uploadFixture(t *testing.T, s lifecycle) string {
	t.Helper()
	raw, key := archiveFixture(t, nil, false)
	return putUploadFixture(t, s, raw, key)
}

func putUploadFixture(t *testing.T, s lifecycle, raw []byte, key ed25519.PublicKey) string {
	t.Helper()
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
	return token
}

func TestSignedInstallPlanPreservesDisabledRootAndBindsArchiveAndRegistry(t *testing.T) {
	s := fixtureLifecycle(t)
	token := uploadFixture(t, s)
	old := fixtureManifest(t)
	old["version"] = "0.9.0"
	old["enabled"] = false
	old["signer"] = "fixture"
	if err := s.saveRegistry(Registry{"example": old}); err != nil {
		t.Fatal(err)
	}
	prepared, err := s.prepare(context.Background(), "module.install", map[string]any{"upload": token}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.archive.Close()
	if prepared.target != "example" || !reflect.DeepEqual(prepared.order, []string{"example"}) || !strings.Contains(string(prepared.result), "Update (remains disabled): Example 1.0.0") {
		t.Fatal(string(prepared.result), prepared.order)
	}
	if prepared.fingerprint == "" {
		t.Fatal("missing fingerprint")
	}
	old["enabled"] = true
	if err = s.saveRegistry(Registry{"example": old}); err != nil {
		t.Fatal(err)
	}
	changed, err := s.prepare(context.Background(), "module.install", map[string]any{"upload": token}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer changed.archive.Close()
	if prepared.fingerprint == changed.fingerprint {
		t.Fatal("registry drift did not invalidate plan")
	}
	if _, err = s.prepare(context.Background(), "module.install", map[string]any{"upload": token}, "bob"); err == nil {
		t.Fatal("another actor upload accepted")
	}
}

func TestEnablePlansDisabledDependenciesAndRemovalRefusesDependents(t *testing.T) {
	s := fixtureLifecycle(t)
	app := fixtureManifest(t)
	app["enabled"] = false
	app["dependencies"] = map[string]any{"dep": ">=1.0.0"}
	dep := fixtureManifest(t)
	dep["id"] = "dep"
	dep["enabled"] = false
	if err := s.saveRegistry(Registry{"example": app, "dep": dep}); err != nil {
		t.Fatal(err)
	}
	plan, err := s.prepare(context.Background(), "module.enable", map[string]any{"target": "example"}, "alice")
	if err != nil || !reflect.DeepEqual(plan.order, []string{"dep", "example"}) {
		t.Fatal(plan, err)
	}
	for _, action := range []string{"module.disable", "module.remove"} {
		if _, err = s.prepare(context.Background(), action, map[string]any{"target": "dep"}, "alice"); err == nil || !strings.Contains(err.Error(), "Dependent modules: example") {
			t.Fatal(err)
		}
	}
	for _, target := range []string{"../other", "missing"} {
		if _, err = s.prepare(context.Background(), "module.remove", map[string]any{"target": target}, "alice"); err == nil {
			t.Fatal("unsafe target accepted", target)
		}
	}
}

func TestPlanRequiresExplicitRecordedRecoveryAndBindsJournal(t *testing.T) {
	s := fixtureLifecycle(t)
	if _, err := s.plan(context.Background(), "module.recover", map[string]any{}, "alice"); err == nil {
		t.Fatal("recovery without journal planned")
	}
	if err := os.Mkdir(filepath.Join(s.root, ".transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	state := validTransaction(s.owner)
	if err := s.saveTransaction(state); err != nil {
		t.Fatal(err)
	}
	if _, err := s.plan(context.Background(), "module.enable", map[string]any{"target": "example"}, "alice"); err == nil || !strings.Contains(err.Error(), "Recover the recorded") {
		t.Fatal(err)
	}
	first, err := s.prepare(context.Background(), "module.recover", map[string]any{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	state.Phase = "switching"
	if err = s.saveTransaction(state); err != nil {
		t.Fatal(err)
	}
	second, err := s.prepare(context.Background(), "module.recover", map[string]any{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if first.fingerprint == second.fingerprint || second.target != "modules" {
		t.Fatal(first, second)
	}
	var response map[string]any
	if err = json.Unmarshal(second.result, &response); err != nil || response["confirmation"] != "modules" {
		t.Fatal(response, err)
	}
}

func TestUploadOwnershipAndPathValidationBeforeInspection(t *testing.T) {
	for _, variant := range []string{"symlink", "hardlink", "writable", "unsafe-name", "bad-token"} {
		t.Run(variant, func(t *testing.T) {
			s := fixtureLifecycle(t)
			token := uploadFixture(t, s)
			name := "alice"
			path := filepath.Join(s.uploads, "alice-"+token+".zip")
			switch variant {
			case "symlink":
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".saved", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".linked"); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "unsafe-name":
				name = "../alice"
			case "bad-token":
				token = "../" + token
			}
			if file, _, err := s.openUpload(token, name); err == nil {
				file.Close()
				t.Fatal("untrusted upload opened")
			}
		})
	}
}

func TestModulePlanFingerprintBindsPayloadUnitAndMountSafety(t *testing.T) {
	s := fixtureLifecycle(t)
	manifest := fixtureManifest(t)
	manifest["enabled"] = false
	if err := s.saveRegistry(Registry{"example": manifest}); err != nil {
		t.Fatal(err)
	}
	fingerprint := func() string {
		t.Helper()
		p, err := s.prepare(context.Background(), "module.enable", map[string]any{"target": "example"}, "alice")
		if err != nil {
			t.Fatal(err)
		}
		return p.fingerprint
	}
	first := fingerprint()
	if err := os.Mkdir(filepath.Join(s.root, "example"), 0755); err != nil {
		t.Fatal(err)
	}
	second := fingerprint()
	if first == second {
		t.Fatal("new payload incarnation did not invalidate plan")
	}
	if err := os.WriteFile(filepath.Join(s.units, unit("example")), []byte("root-owned before unit"), 0644); err != nil {
		t.Fatal(err)
	}
	third := fingerprint()
	if second == third {
		t.Fatal("service configuration did not invalidate plan")
	}
	if err := os.Chmod(filepath.Join(s.units, unit("example")), 0640); err != nil {
		t.Fatal(err)
	}
	if third == fingerprint() {
		t.Fatal("service metadata did not invalidate plan")
	}
	s.mounts = func() ([]string, error) { return []string{filepath.Join(s.root, "example/data")}, nil }
	if _, err := s.prepare(context.Background(), "module.enable", map[string]any{"target": "example"}, "alice"); err == nil {
		t.Fatal("nested mounted data omitted from module preflight")
	}
}
