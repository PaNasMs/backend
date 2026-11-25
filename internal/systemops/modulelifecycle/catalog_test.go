package modulelifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"maps"
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

// tamperCatalogSignature keeps the trusted signer and algorithm and flips one
// bit of the ed25519 signature, so only signature verification can reject it.
func tamperCatalogSignature(t *testing.T, files map[string][]byte) {
	t.Helper()
	var env catalogEnvelope
	if e := json.Unmarshal(files[fixtureBase+"catalog.sig"], &env); e != nil || len(env.Signature) != ed25519.SignatureSize {
		t.Fatal(env, e)
	}
	env.Signature[0] ^= 1
	files[fixtureBase+"catalog.sig"] = mustJSON(t, env)
}

// snapshotState records every file below the module configuration directory
// (sources, pending intent and trusted keys) and the raw bytes of
// registry.json, so a rewrite with equivalent contents still counts as a
// change.
func snapshotState(t *testing.T, s lifecycle) map[string]string {
	t.Helper()
	out := map[string]string{}
	root := filepath.Dir(s.keys)
	if e := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		out[path] = string(raw)
		return err
	}); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(s.root, "registry.json"))
	switch {
	case os.IsNotExist(e):
		out["registry"] = "<absent>"
	case e != nil:
		t.Fatal(e)
	default:
		out["registry"] = "present:" + string(raw)
	}
	return out
}

// A rejected operation that writes registry.json with equivalent contents
// must be visible to snapshotState.
func TestSnapshotStateSeesRegistryRewrite(t *testing.T) {
	s, _, _ := catalogFixture(t)
	path := filepath.Join(s.root, "registry.json")
	before := snapshotState(t, s)
	if e := os.WriteFile(path, []byte("{}"), 0644); e != nil {
		t.Fatal(e)
	}
	created := snapshotState(t, s)
	if maps.Equal(before, created) {
		t.Fatal("registry.json was created but snapshotState reports unchanged state")
	}
	if e := os.WriteFile(path, []byte("{ }"), 0644); e != nil {
		t.Fatal(e)
	}
	if maps.Equal(created, snapshotState(t, s)) {
		t.Fatal("registry.json was rewritten but snapshotState reports unchanged state")
	}
}

func assertRejected(t *testing.T, e error, want string) {
	t.Helper()
	if e == nil || e.Error() != want {
		t.Fatalf("got error %v, want %q", e, want)
	}
}

func TestTamperedCatalogSignatureRejected(t *testing.T) {
	ctx := context.Background()
	t.Run("source-add", func(t *testing.T) {
		s, f, key := catalogFixture(t)
		// The publisher key is already trusted locally and is the one the
		// repository serves, so discovery reaches signature verification.
		if e := os.WriteFile(filepath.Join(s.keys, "catalog.pem"), f[fixtureBase+"keys/catalog.pem"], 0644); e != nil {
			t.Fatal(e)
		}
		signCatalogFixture(t, f, key, []any{})
		before := snapshotState(t, s)
		p := map[string]any{"url": fixtureBase}
		signed := f[fixtureBase+"catalog.json"]
		f[fixtureBase+"catalog.json"] = mustJSON(t, Manifest{"schemaVersion": 1, "id": "other-repo", "modules": []any{}})
		_, e := s.prepare(ctx, "module.source-add", p, "alice")
		assertRejected(t, e, "Invalid module catalog signature")
		f[fixtureBase+"catalog.json"] = signed
		tamperCatalogSignature(t, f)
		_, e = s.prepare(ctx, "module.source-add", p, "alice")
		assertRejected(t, e, "Invalid module catalog signature")
		_, e = s.execute(ctx, "module.source-add", p, "alice", "any", nil, func() error { return nil })
		assertRejected(t, e, "Invalid module catalog signature")
		if after := snapshotState(t, s); !maps.Equal(before, after) {
			t.Fatalf("state changed:\n%v\n%v", before, after)
		}
	})
	t.Run("configured-source", func(t *testing.T) {
		s, f, key := catalogFixture(t)
		dir, e := s.configDir()
		if e != nil {
			t.Fatal(e)
		}
		defer dir.Close()
		src := Manifest{"id": "demo-repo", "url": fixtureBase, "signers": []any{"catalog"}, "official": false}
		if e = atomicAt(dir, sourceFile, mustJSON(t, []Manifest{src}), 0600, s.owner); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(s.keys, "catalog.pem"), f[fixtureBase+"keys/catalog.pem"], 0644); e != nil {
			t.Fatal(e)
		}
		signCatalogFixture(t, f, key, []any{})
		if _, e = s.readCatalog(ctx, src); e != nil {
			t.Fatal("valid catalog rejected:", e)
		}
		tamperCatalogSignature(t, f)
		before := snapshotState(t, s)
		_, e = s.readCatalog(ctx, src)
		assertRejected(t, e, "Invalid module catalog signature")
		list, e := s.catalogAvailable(ctx)
		if e != nil {
			t.Fatal(e)
		}
		var got struct {
			Available []Manifest
			Errors    []Manifest
		}
		if e = json.Unmarshal(list, &got); e != nil || len(got.Available) != 0 || len(got.Errors) != 1 ||
			got.Errors[0]["repository"] != "demo-repo" || got.Errors[0]["error"] != "Invalid module catalog signature" {
			t.Fatal(string(list), e)
		}
		if after := snapshotState(t, s); !maps.Equal(before, after) {
			t.Fatalf("state changed:\n%v\n%v", before, after)
		}
	})
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
	rows, e = s.sources()
	if e != nil || len(rows) != 1 || rows[0]["id"] != "legacy-repo" || rows[0]["extra"] != "keep" {
		t.Fatal(rows, e)
	}
	if _, e = os.Stat(filepath.Join(dir.Name(), sourceIntent)); !os.IsNotExist(e) {
		t.Fatal("pending source change retained", e)
	}
}
// A crash leaves a durable repository change. Package changes must wait for
// the installed version to finish it; otherwise a downgraded version edits
// sources without knowing the intent and the next upgrade replays it.
func TestCheckInstallHonorsPendingSourceChange(t *testing.T) {
	s, f, key := catalogFixture(t)
	ctx := context.Background()
	dir, e := s.configDir()
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	legacy := Manifest{"id": "legacy-repo", "signers": []any{"other"}, "url": "https://example.net/"}
	if e = atomicAt(dir, sourceFile, mustJSON(t, []Manifest{legacy}), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	signCatalogFixture(t, f, key, []any{})
	plan, e := s.prepare(ctx, "module.source-add", map[string]any{"url": fixtureBase}, "alice")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.checkInstall(); e != nil {
		t.Fatal("clean state refused", e)
	}
	// Crash after the durable decision and key write, before the config rename.
	if e = atomicAt(dir, sourceIntent, mustJSON(t, plan.source), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(s.keys, "catalog.pem"), plan.source.Key, 0644); e != nil {
		t.Fatal(e)
	}
	before := snapshotState(t, s)
	assertRejected(t, s.checkInstall(), "Recover pending module transactions with the installed version before package changes")
	if after := snapshotState(t, s); !maps.Equal(before, after) {
		t.Fatalf("check-install changed state:\n%v\n%v", before, after)
	}
	// An unreadable intent must not pass as clean either.
	if e = atomicAt(dir, sourceIntent, []byte("{"), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	if e = s.checkInstall(); e == nil {
		t.Fatal("corrupt pending source change accepted")
	}
	if e = atomicAt(dir, sourceIntent, mustJSON(t, plan.source), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	// The installed version finishes the change; only then may the package move.
	if e = s.recoverStartup(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.checkInstall(); e != nil {
		t.Fatal("recovered state refused", e)
	}
	// Downgrade: an older version removes the repository without the intent
	// protocol. The following upgrade must not replay the finished change.
	if e = atomicAt(dir, sourceFile, mustJSON(t, []Manifest{legacy}), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(s.keys, "catalog.pem")); e != nil {
		t.Fatal(e)
	}
	if e = s.checkInstall(); e != nil {
		t.Fatal(e)
	}
	before = snapshotState(t, s)
	if e = s.recoverStartup(ctx); e != nil {
		t.Fatal(e)
	}
	if after := snapshotState(t, s); !maps.Equal(before, after) {
		t.Fatalf("upgrade replayed an old source change:\n%v\n%v", before, after)
	}
	if rows, e := s.sources(); e != nil || len(rows) != 1 || rows[0]["id"] != "legacy-repo" {
		t.Fatal(rows, e)
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
	if e != nil {
		t.Fatal(e)
	}
	var listing struct {
		Available []Manifest
		Errors    []Manifest
	}
	if e = json.Unmarshal(list, &listing); e != nil || len(listing.Errors) != 0 || len(listing.Available) != 1 {
		t.Fatal(string(list), e)
	}
	if got := listing.Available[0]; got["id"] != "example" || got["version"] != "1.0.0" || got["signer"] != "fixture" ||
		got["repository"] != "demo-repo" || got["reason"] != "" || got["updateAvailable"] != false {
		t.Fatal(string(list))
	}
	p := map[string]any{"version": "1.0.0", "target": "example"}
	fp := executionPlan(t, s, "module.catalog-install", p)
	// The replacement download is valid and matches the catalog entry, so
	// only the stale plan fingerprint can reject the install.
	f[fixtureBase+"replacement.zip"] = raw
	entry["url"] = fixtureBase + "replacement.zip"
	signCatalogFixture(t, f, priv, modules)
	if got, e := s.catalogFetch(ctx, fixtureBase+"replacement.zip", int64(len(raw))); e != nil || sha256.Sum256(got) != sum {
		t.Fatal("replacement archive is not usable", e)
	}
	replaced := executionPlan(t, s, "module.catalog-install", p)
	if replaced == fp {
		t.Fatal("replacement release did not change the plan")
	}
	_, e = s.execute(ctx, "module.catalog-install", p, "alice", fp, nil, func() error { return nil })
	assertRejected(t, e, "State has changed. Review a new operation plan.")
	if reg, e := s.registry(); e != nil || len(reg) != 0 {
		t.Fatal("stale plan changed state", reg, e)
	}
	entry["url"] = url
	signCatalogFixture(t, f, priv, modules)
	f[url] = append([]byte{}, raw...)
	f[url][0] ^= 1
	_, e = s.execute(ctx, "module.catalog-install", p, "alice", fp, nil, func() error { return nil })
	assertRejected(t, e, "Module archive checksum mismatch: example")
	if reg, e := s.registry(); e != nil || len(reg) != 0 {
		t.Fatal("digest mismatch changed state", reg, e)
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
