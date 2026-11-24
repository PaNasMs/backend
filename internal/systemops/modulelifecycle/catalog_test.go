package modulelifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"panasms.local/backend/internal/systemops"
	"path/filepath"
	"slices"
	"testing"
)

const fixtureBase = "https://example.org/modules/"

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func catalogFixture(t *testing.T) (lifecycle, map[string][]byte, ed25519.PrivateKey) {
	t.Helper()
	s := executionFixture(t)
	dir := t.TempDir()
	s.keys = filepath.Join(dir, "module-keys")
	if e := os.Mkdir(s.keys, 0700); e != nil {
		t.Fatal(e)
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		t.Fatal(e)
	}
	files := map[string][]byte{fixtureBase + "keys/catalog.pem": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}
	s.catalogFetch = func(_ context.Context, u string, limit int64) ([]byte, error) {
		b, ok := files[u]
		if !ok || int64(len(b)) > limit {
			return nil, reject("Download unavailable")
		}
		return b, nil
	}
	return s, files, priv
}
func signCatalogFixture(t *testing.T, files map[string][]byte, priv ed25519.PrivateKey, modules any) {
	t.Helper()
	raw := mustJSON(t, Manifest{"schemaVersion": 1, "id": "demo-repo", "modules": modules})
	files[fixtureBase+"catalog.json"] = raw
	files[fixtureBase+"catalog.sig"] = mustJSON(t, catalogEnvelope{Algorithm: "Ed25519", Signer: "catalog", Signature: ed25519.Sign(priv, raw)})
}
func TestSourceTrustStalePlanAndRestart(t *testing.T) {
	s, f, key := catalogFixture(t)
	ctx := context.Background()
	p := map[string]any{"url": fixtureBase}
	dir, e := s.configDir()
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	legacy := Manifest{"id": "legacy-repo", "signers": []any{"other"}, "url": "https://example.net/", "extra": "keep"}
	if e = atomicAt(dir, sourceFile, mustJSON(t, []Manifest{legacy}), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	signCatalogFixture(t, f, key, []any{})
	sig := f[fixtureBase+"catalog.sig"]
	delete(f, fixtureBase+"catalog.sig")
	if _, e = s.prepare(ctx, "module.source-add", p, "alice"); e == nil {
		t.Fatal("accepted unsigned source")
	}
	f[fixtureBase+"catalog.sig"] = mustJSON(t, catalogEnvelope{Signer: "wrong", Algorithm: "Ed25519"})
	if _, e = s.prepare(ctx, "module.source-add", p, "alice"); e == nil {
		t.Fatal("accepted untrusted signer")
	}
	f[fixtureBase+"catalog.sig"] = sig
	plan, e := s.prepare(ctx, "module.source-add", p, "alice")
	if e != nil {
		t.Fatal(e)
	}
	p["keyFingerprint"] = plan.source.Sources[1]["fingerprint"]
	if _, e = s.execute(ctx, "module.source-add", p, "alice", "stale", nil, func() error { return nil }); e == nil {
		t.Fatal("accepted stale approval")
	}
	if _, e = s.execute(ctx, "module.source-add", p, "alice", plan.fingerprint, nil, func() error { return reject("role changed") }); e == nil {
		t.Fatal("accepted unauthorized change")
	}
	rows, e := s.sources()
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	if _, e = os.Stat(filepath.Join(s.keys, "catalog.pem")); !os.IsNotExist(e) {
		t.Fatal("unexpected key", e)
	}
	// A crash after the durable decision and key write but before config rename.
	if e = atomicAt(dir, sourceIntent, mustJSON(t, plan.source), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(s.keys, "catalog.pem"), plan.source.Key, 0644); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e = s.recoverStartup(ctx); e != nil {
			t.Fatal(e)
		}
		rows, e = s.sources()
		if e != nil || len(rows) != 2 || rows[0]["extra"] != "keep" || rows[1]["id"] != "demo-repo" {
			t.Fatal(rows, e)
		}
	}
	remove := map[string]any{"target": "demo-repo"}
	fp := executionPlan(t, s, "module.source-remove", remove)
	if _, e = s.execute(ctx, "module.source-remove", remove, "alice", fp, nil, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(s.keys, "catalog.pem")); !os.IsNotExist(e) {
		t.Fatal("removed key still present", e)
	}
}
func TestSignedCatalogInstall(t *testing.T) {
	s, f, priv := catalogFixture(t)
	s.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
		if !slices.Equal(argv, []string{"systemctl", "daemon-reload"}) {
			t.Fatalf("unexpected command %q", argv)
		}
		return nil, nil
	}
	ctx := context.Background()
	raw, key := archiveFixture(t, nil, false)
	putUploadFixture(t, s, raw, key)
	bundle, e := inspectFixture(raw, key)
	if e != nil {
		t.Fatal(e)
	}
	src := Manifest{"id": "demo-repo", "url": fixtureBase, "signers": []any{"catalog", "fixture"}, "official": false}
	dir, e := s.configDir()
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	if e = atomicAt(dir, sourceFile, mustJSON(t, []Manifest{src}), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(s.keys, "catalog.pem"), f[fixtureBase+"keys/catalog.pem"], 0644); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	url := fixtureBase + "example.zip"
	f[url] = raw
	entry := Manifest{"channel": "stable", "manifest": bundle.manifests["example"], "sha256": hex.EncodeToString(sum[:]), "size": len(raw), "url": url}
	modules := []Manifest{{"id": "example", "releases": []Manifest{entry}}}
	signCatalogFixture(t, f, priv, modules)
	list, e := s.catalogAvailable(ctx)
	if e != nil || !bytes.Contains(list, []byte(`"reason":""`)) {
		t.Fatal(string(list), e)
	}
	p := map[string]any{"version": "1.0.0", "target": "example"}
	fp := executionPlan(t, s, "module.catalog-install", p)
	entry["url"] = fixtureBase + "replacement.zip"
	signCatalogFixture(t, f, priv, modules)
	if _, e = s.execute(ctx, "module.catalog-install", p, "alice", fp, nil, func() error { return nil }); e == nil {
		t.Fatal("accepted stale catalog")
	}
	entry["url"] = url
	signCatalogFixture(t, f, priv, modules)
	f[url] = append([]byte{}, raw...)
	f[url][0] ^= 1
	if _, e = s.execute(ctx, "module.catalog-install", p, "alice", fp, nil, func() error { return nil }); e == nil {
		t.Fatal("ignored digest mismatch")
	}
	f[url] = raw
	result, e := s.execute(ctx, "module.catalog-install", p, "alice", fp, nil, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	reg, e := s.registry()
	if e != nil || reg["example"]["version"] != "1.0.0" || reg["example"]["enabled"] != true {
		t.Fatal(reg, string(result), e)
	}
}
