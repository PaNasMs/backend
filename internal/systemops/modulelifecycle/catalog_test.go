package modulelifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"panasms.local/backend/internal/systemops"
)

func catalogFixture(t *testing.T) (catalogService, func(string, bool)) {
	t.Helper()
	s := executionFixture(t)
	c := catalogService{lifecycle: s, config: filepath.Join(s.root, "sources.json")}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(s.keys, "fixture.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	write(c.config, []byte(`[{"id":"fixture","url":"https://example.org/","signers":["fixture"],"official":false}]`))
	served := map[string][]byte{"https://example.org/keys/fixture.pem": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}
	c.download = func(_ context.Context, u string, _ int64, _ downloadKind) ([]byte, error) {
		raw, ok := served[u]
		if !ok {
			return nil, reject("Fixture unavailable")
		}
		return raw, nil
	}
	return c, func(version string, valid bool) {
		raw, _ := json.Marshal(map[string]any{"schemaVersion": 1, "id": "fixture", "modules": []any{map[string]any{"id": "example", "releases": []any{map[string]any{"manifest": map[string]any{"id": "example", "version": version, "signer": "fixture"}, "url": "https://example.org/archive", "size": 1, "sha256": strings.Repeat("0", 64), "channel": "stable"}}}}})
		sig := ed25519.Sign(private, raw)
		if !valid {
			sig[0] ^= 1
		}
		envelope, _ := json.Marshal(map[string]any{"algorithm": "Ed25519", "signer": "fixture", "signature": base64.StdEncoding.EncodeToString(sig)})
		served["https://example.org/catalog.json"], served["https://example.org/catalog.sig"] = raw, envelope
	}
}

func visibleCatalog(t *testing.T, c catalogService, version string, wantError bool) {
	t.Helper()
	raw, err := c.query(context.Background(), "module-catalog")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Available []struct{ Version string }
		Errors    []map[string]string
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Available) != 1 || result.Available[0].Version != version || (len(result.Errors) > 0) != wantError {
		t.Fatal(string(raw))
	}
}

func catalogCacheBytes(t *testing.T, c catalogService) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.root, ".catalog-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestSignedRefreshReplacesVerifiedGeneration(t *testing.T) {
	c, serve := catalogFixture(t)
	serve("1.0.0", true)
	visibleCatalog(t, c, "1.0.0", false)
	before := catalogCacheBytes(t, c)
	serve("2.0.0", true)
	visibleCatalog(t, c, "2.0.0", false)
	if before == catalogCacheBytes(t, c) {
		t.Fatal("verified generation was not replaced")
	}
}

func TestInvalidRefreshPreservesVerifiedGenerationAcrossRestart(t *testing.T) {
	c, serve := catalogFixture(t)
	serve("1.0.0", true)
	visibleCatalog(t, c, "1.0.0", false)
	before := catalogCacheBytes(t, c)
	serve("2.0.0", false)
	visibleCatalog(t, c, "1.0.0", true)
	restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
	visibleCatalog(t, restarted, "1.0.0", true)
	if before != catalogCacheBytes(t, c) {
		t.Fatal("rejected generation changed cache bytes")
	}
}

func TestSourceInterruptionRecoversWithoutChangingInstalledModules(t *testing.T) {
	for _, tc := range []struct {
		action, phase string
		committed     bool
	}{
		{"module.source-add", "key-written", false},
		{"module.source-add", "config-written", true},
		{"module.source-remove", "config-written", true},
	} {
		t.Run(tc.action+"/"+tc.phase, func(t *testing.T) {
			c, serve := catalogFixture(t)
			serve("1.0.0", true)
			manifest := fixtureManifest(t)
			manifest["signer"] = "fixture"
			if err := c.saveRegistry(Registry{"example": manifest}); err != nil {
				t.Fatal(err)
			}
			registryPath := filepath.Join(c.root, "registry.json")
			before, err := os.ReadFile(registryPath)
			if err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(c.keys, "fixture.pem")
			params := map[string]any{"target": "fixture"}
			if tc.action == "module.source-add" {
				if err = os.Remove(key); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(c.config, []byte(`[]`), 0600); err != nil {
					t.Fatal(err)
				}
				raw, err := c.planCatalog(context.Background(), tc.action, map[string]any{"url": "https://example.org"})
				if err != nil {
					t.Fatal(err)
				}
				var plan map[string]any
				if err = json.Unmarshal(raw, &plan); err != nil {
					t.Fatal(err)
				}
				params = map[string]any{"url": "https://example.org", "keyFingerprint": plan["publisherFingerprint"]}
			}
			fp := catalogPlanFingerprint(t, c, tc.action, params)
			stopped := errors.New("fixture interrupted")
			c.sourceBoundary = func(phase string) error {
				if phase == tc.phase {
					return stopped
				}
				return nil
			}
			outcome, err := c.executeCatalog(context.Background(), tc.action, params, fp, nil, func() error { return nil })
			if tc.committed {
				if err != nil || !strings.Contains(string(outcome), `"warnings"`) {
					t.Fatal(string(outcome), err)
				}
			} else if !errors.Is(err, stopped) {
				t.Fatal(err)
			}
			if _, err = c.prepare(context.Background(), "module.install", map[string]any{}, "alice"); err == nil || !strings.Contains(err.Error(), "interrupted module repository") {
				t.Fatal("direct install did not block pending source trust", err)
			}
			other := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
			result, err := other.recoverCatalog(context.Background(), tc.action)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(result), "has not been repeated") {
				t.Fatal(string(result))
			}
			rows, err := other.sources()
			if err != nil {
				t.Fatal(err)
			}
			wantPresent := tc.action == "module.source-add" && tc.committed
			if (len(rows) == 1) != wantPresent {
				t.Fatal(rows)
			}
			if _, err = os.Stat(key); (err == nil) != wantPresent {
				t.Fatal(err)
			}
			if _, err = os.Stat(filepath.Join(c.root, sourceIntent)); !os.IsNotExist(err) {
				t.Fatal(err)
			}
			after, err := os.ReadFile(registryPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("registry changed", err)
			}
		})
	}
}

func catalogPlanFingerprint(t *testing.T, c catalogService, action string, params map[string]any) string {
	t.Helper()
	raw, err := c.planCatalog(context.Background(), action, params)
	if err != nil {
		t.Fatal(err)
	}
	var result struct{ Fingerprint string }
	if err = json.Unmarshal(raw, &result); err != nil || result.Fingerprint == "" {
		t.Fatal(string(raw), err)
	}
	return result.Fingerprint
}

func installCatalogFixture(t *testing.T, badSignature bool) (catalogService, map[string][]byte, func(string)) {
	t.Helper()
	c, _ := catalogFixture(t)
	raw, public := archiveFixture(t, nil, false)
	want, err := inspectFixture(raw, public)
	if err != nil {
		t.Fatal(err)
	}
	if badSignature {
		raw, public = archiveFixture(t, nil, true)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(c.keys, "fixture.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	catalogKey, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	catalogDER, err := x509.MarshalPKIXPublicKey(catalogKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(c.keys, "registry.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: catalogDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(c.config, []byte(`[{"id":"fixture","url":"https://example.org/","signers":["registry","fixture"],"official":false}]`), 0600); err != nil {
		t.Fatal(err)
	}
	served := map[string][]byte{"https://example.org/archive": raw}
	c.download = func(_ context.Context, u string, _ int64, _ downloadKind) ([]byte, error) {
		data, ok := served[u]
		if !ok {
			return nil, reject("Unavailable fixture")
		}
		return data, nil
	}
	publish := func(url string) {
		sum := sha256.Sum256(raw)
		entry := map[string]any{"manifest": want.manifests["example"], "url": url, "size": len(raw), "sha256": hex.EncodeToString(sum[:]), "channel": "stable"}
		data, err := json.Marshal(map[string]any{"id": "fixture", "schemaVersion": 1, "modules": []any{map[string]any{"id": "example", "releases": []any{entry}}}})
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := json.Marshal(map[string]any{"signer": "registry", "algorithm": "Ed25519", "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, data))})
		if err != nil {
			t.Fatal(err)
		}
		served["https://example.org/catalog.json"], served["https://example.org/catalog.sig"] = data, envelope
	}
	publish("https://example.org/archive")
	return c, served, publish
}

func assertCatalogStageClean(t *testing.T, c catalogService) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(c.root, catalogStage, stageArchive)); !os.IsNotExist(err) {
		t.Fatal("Staged archive survived", err)
	}
}

func TestCatalogInstallRefusesStaleSelectedRelease(t *testing.T) {
	c, _, publish := installCatalogFixture(t, false)
	p := map[string]any{"target": "example", "version": "1.0.0"}
	fp := catalogPlanFingerprint(t, c, "module.catalog-install", p)
	publish("https://example.org/replacement")
	_, err := c.executeCatalog(context.Background(), "module.catalog-install", p, fp, nil, func() error { return nil })
	if !systemops.Unchanged(err) || !strings.Contains(err.Error(), "State has changed") {
		t.Fatal(err)
	}
	assertCatalogStageClean(t, c)
}

func TestCatalogInstallRefusesInvalidArchiveSignatureAndCleansStaging(t *testing.T) {
	c, _, _ := installCatalogFixture(t, true)
	p := map[string]any{"target": "example", "version": "1.0.0"}
	fp := catalogPlanFingerprint(t, c, "module.catalog-install", p)
	_, err := c.executeCatalog(context.Background(), "module.catalog-install", p, fp, nil, func() error { return nil })
	if !systemops.Unchanged(err) || !strings.Contains(err.Error(), "Invalid module signature") {
		t.Fatal(err)
	}
	assertCatalogStageClean(t, c)
}

func TestCatalogInstallUsesNativeLifecycleAndCleansStaging(t *testing.T) {
	c, _, _ := installCatalogFixture(t, false)
	p := map[string]any{"target": "example", "version": "1.0.0"}
	fp := catalogPlanFingerprint(t, c, "module.catalog-install", p)
	commands := 0
	c.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) { commands++; return nil, nil }
	_, err := c.executeCatalog(context.Background(), "module.catalog-install", p, fp, nil, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	registry, err := c.registry()
	if err != nil || text(registry["example"], "version") != "1.0.0" || commands == 0 {
		t.Fatal(registry, commands, err)
	}
	assertCatalogStageClean(t, c)
}

func TestInterruptedCatalogInstallRecoveryDoesNotReplay(t *testing.T) {
	c, _, _ := installCatalogFixture(t, false)
	ctx := context.Background()
	dir, err := c.catalogLock(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := c.selectRelease(ctx, dir, map[string]any{"target": "example", "version": "1.0.0"})
	if err != nil {
		dir.Close()
		t.Fatal(err)
	}
	err = c.stageCatalogInstall(ctx, dir, plan, nil)
	dir.Close()
	if err != nil {
		t.Fatal(err)
	}
	lc := c.lifecycle
	lc.uploads = filepath.Join(c.root, catalogStage)
	native, err := lc.prepare(ctx, "module.install", map[string]any{"upload": stagedToken}, stageOwner)
	if err != nil {
		t.Fatal(err)
	}
	defer native.archive.Close()
	if _, err = lc.begin("module.install", native); err != nil {
		t.Fatal(err)
	}
	restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: func(context.Context, string, int64, downloadKind) ([]byte, error) {
		t.Fatal("Recovery attempted to download")
		return nil, nil
	}}
	if err := os.WriteFile(c.config, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, wantChanged := range []bool{true, false} {
		var changed bool
		raw, err := restarted.recoverCatalog(TrackSourceRepair(ctx, &changed), "module.catalog-install")
		if err != nil || !strings.Contains(string(raw), `"recoveryAction":"module.recover"`) ||
			!strings.Contains(string(raw), "Invalid module repository configuration") || changed != wantChanged {
			t.Fatalf("recovery report %s, changed=%v, error=%v", raw, changed, err)
		}
		assertCatalogStageClean(t, restarted)
	}
	state, err := restarted.loadTransaction()
	if err != nil || state == nil || state.Committed {
		t.Fatal(state, err)
	}
	registry, err := restarted.registry()
	if err != nil || len(registry) != 0 {
		t.Fatal(registry, err)
	}
}

func TestCatalogSourceDefaultsAndExplicitEmptyFingerprint(t *testing.T) {
	c, _ := catalogFixture(t)
	if err := os.Remove(c.config); err != nil {
		t.Fatal(err)
	}
	rows, err := c.sources()
	if err != nil || len(rows) != 1 || text(rows[0], "id") != officialID {
		t.Fatal(rows, err)
	}
	if err = os.WriteFile(c.config, []byte(`[]`), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := c.query(context.Background(), "module-sources")
	if err != nil || string(raw) != `{"sources":[]}` {
		t.Fatal(string(raw), err)
	}
	// Computed with management/common.py fingerprint over the original Python plan state.
	want := "65d0dcbe3821d21aa3d38784e263c9c89c6e394d1f9bcf7cb403183902f2998c"
	if got := catalogPlanFingerprint(t, c, "module.source-add", map[string]any{"url": officialURL}); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestRevokedCatalogKeyCannotExposeCachedRelease(t *testing.T) {
	c, serve := catalogFixture(t)
	serve("1.0.0", true)
	visibleCatalog(t, c, "1.0.0", false)
	if err := os.Remove(filepath.Join(c.keys, "fixture.pem")); err != nil {
		t.Fatal(err)
	}
	raw, err := c.query(context.Background(), "module-catalog")
	if err != nil || !strings.Contains(string(raw), `"available":[]`) {
		t.Fatal(string(raw), err)
	}
}

func TestSourceDefaultsEmptyAndPythonFingerprint(t *testing.T) {
	c, _ := catalogFixture(t)
	if err := os.Remove(c.config); err != nil {
		t.Fatal(err)
	}
	p := map[string]any{"target": "panasms-official"}
	fp := catalogPlanFingerprint(t, c, "module.source-remove", p)
	// Calculated with management/common.py using the absent-file default.
	if fp != "5966500e72077c349339e19a6b2c30e9d0ac377e528f61e59365aaf65d27556c" {
		t.Fatal(fp)
	}
	if _, err := c.executeCatalog(context.Background(), "module.source-remove", p, fp, nil, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	r, err := c.query(context.Background(), "module-sources")
	if err != nil || string(r) != `{"sources":[]}` {
		t.Fatal(string(r), err)
	}
}

func TestSourceRevocationHidesCachedEntries(t *testing.T) {
	c, serve := catalogFixture(t)
	serve("1.0.0", true)
	visibleCatalog(t, c, "1.0.0", false)
	p := map[string]any{"target": "fixture"}
	fp := catalogPlanFingerprint(t, c, "module.source-remove", p)
	if _, err := c.executeCatalog(context.Background(), "module.source-remove", p, fp, nil, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	raw, err := c.query(context.Background(), "module-catalog")
	if err != nil || string(raw) != `{"available":[],"errors":[]}` {
		t.Fatal(string(raw), err)
	}
	if _, err = os.Stat(filepath.Join(c.root, catalogCacheName("fixture"))); !os.IsNotExist(err) {
		t.Fatal("retired cache remained", err)
	}
}

func TestCatalogUsesConfiguredOrderNotNewestAcrossRepositories(t *testing.T) {
	c, serve := catalogFixture(t)
	serve("1.0.0", true)
	config := `[{"id":"fixture","url":"https://example.org/","signers":["fixture"],"official":false},{"id":"other","url":"https://example.net/","signers":["other"],"official":false}]`
	if err := os.WriteFile(c.config, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(c.keys, "other.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	first := c.download
	raw, err := first(context.Background(), "https://example.org/catalog.json", maxCatalog, metadataDownload)
	if err != nil {
		t.Fatal(err)
	}
	second := bytes.ReplaceAll(raw, []byte(`"fixture"`), []byte(`"other"`))
	second = bytes.ReplaceAll(second, []byte(`"1.0.0"`), []byte(`"9.0.0"`))
	envelope, err := json.Marshal(map[string]string{"signer": "other", "algorithm": "Ed25519", "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, second))})
	if err != nil {
		t.Fatal(err)
	}
	c.download = func(ctx context.Context, url string, limit int64, kind downloadKind) ([]byte, error) {
		switch url {
		case "https://example.net/catalog.json":
			return second, nil
		case "https://example.net/catalog.sig":
			return envelope, nil
		}
		return first(ctx, url, limit, kind)
	}
	result, err := c.query(context.Background(), "module-catalog")
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		Available []struct{ Repository, Version string }
		Errors    []map[string]string
	}
	if err = json.Unmarshal(result, &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Available) != 1 || view.Available[0].Repository != "fixture" || view.Available[0].Version != "1.0.0" || len(view.Errors) != 1 || view.Errors[0]["repository"] != "other" || view.Errors[0]["error"] != "Duplicate module ID: example" {
		t.Fatal(string(result))
	}
}

func TestSourceSnapshotDoesNotWaitForCatalogDownload(t *testing.T) {
	c, _ := catalogFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	started, finished := make(chan struct{}), make(chan error, 1)
	c.download = func(ctx context.Context, _ string, _ int64, _ downloadKind) ([]byte, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() {
		_, err := c.query(ctx, "module-catalog")
		finished <- err
	}()
	defer func() { cancel(); <-finished }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("refresh never reached the download")
	}
	snapshotCtx, stop := context.WithTimeout(ctx, 500*time.Millisecond)
	defer stop()
	raw, err := c.query(snapshotCtx, "module-sources")
	if err != nil || !strings.Contains(string(raw), `"id":"fixture"`) {
		t.Fatal(string(raw), err)
	}
}

type catalogTransport func(*http.Request) (*http.Response, error)

func (f catalogTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type stalledCatalogBody struct {
	ctx     context.Context
	started chan struct{}
}

func (b stalledCatalogBody) Read([]byte) (int, error) {
	close(b.started)
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (stalledCatalogBody) Close() error { return nil }

func TestCatalogCancellationInterruptsStalledMetadataAndSmallArchive(t *testing.T) {
	for _, stalledURL := range []string{"https://example.org/catalog.json", "https://example.org/archive"} {
		t.Run(stalledURL, func(t *testing.T) {
			c, _, _ := installCatalogFixture(t, false)
			p := map[string]any{"target": "example", "version": "1.0.0"}
			fp := catalogPlanFingerprint(t, c, "module.catalog-install", p)
			started := make(chan struct{})
			observed := make(chan time.Duration, 1)
			realDownload := downloadWithClient(&http.Client{Transport: catalogTransport(func(req *http.Request) (*http.Response, error) {
				deadline, _ := req.Context().Deadline()
				observed <- time.Until(deadline)
				return &http.Response{StatusCode: 200, Body: stalledCatalogBody{req.Context(), started}}, nil
			})})
			fixture := c.download
			c.download = func(ctx context.Context, url string, limit int64, kind downloadKind) ([]byte, error) {
				if url == stalledURL {
					return realDownload(ctx, url, limit, kind)
				}
				return fixture(ctx, url, limit, kind)
			}
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer read.Close()
			defer write.Close()
			r := systemops.NewReporter(io.Discard, func(string) string { return strconv.FormatUint(uint64(read.Fd()), 10) })
			defer r.Close()
			ctx, cancel := context.WithCancel(context.Background())
			finished := make(chan struct{})
			var executeErr error
			go func() {
				defer close(finished)
				_, executeErr = c.executeCatalog(ctx, "module.catalog-install", p, fp, r, func() error { return nil })
			}()
			defer func() { cancel(); <-finished }()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("body read never started")
			}
			if got := <-observed; stalledURL == "https://example.org/archive" && got < 50*time.Second || stalledURL != "https://example.org/archive" && (got <= 0 || got > 10*time.Second) {
				t.Fatal("unexpected request budget", got)
			}
			if _, err = write.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("reporter did not interrupt the body read")
			}
			if !errors.Is(executeErr, systemops.ErrCancelled) || !systemops.Unchanged(executeErr) {
				t.Fatal(executeErr)
			}
			assertCatalogStageClean(t, c)
		})
	}
}

func TestHostedCatalogInstallReportsStagingCleanupAfterCommit(t *testing.T) {
	c, _, _ := installCatalogFixture(t, false)
	p := map[string]any{"target": "example", "version": "1.0.0"}
	fp := catalogPlanFingerprint(t, c, "module.catalog-install", p)
	c.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
		if strings.Join(argv, " ") == "systemctl daemon-reload" {
			path := filepath.Join(c.root, catalogStage, stageArchive)
			if err := os.Remove(path); err != nil {
				return nil, err
			}
			if err := os.Mkdir(path, 0700); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	raw, err := c.executeCatalog(context.Background(), "module.catalog-install", p, fp, nil, func() error { return nil })
	if err != nil || !strings.Contains(string(raw), `"warnings":["Catalog staging cleanup is incomplete."]`) {
		t.Fatal(string(raw), err)
	}
	registry, err := c.registry()
	if err != nil || text(registry["example"], "version") != "1.0.0" {
		t.Fatal(registry, err)
	}
}

func TestSourceJournalLegacyRemovalAndBoundedWrites(t *testing.T) {
	c, _ := catalogFixture(t)
	ctx := context.Background()
	dir, err := c.catalogLock(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	plan, err := c.planSource(ctx, "module.source-remove", map[string]any{"target": "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := c.keyBytes("fixture")
	if err != nil {
		t.Fatal(err)
	}
	if plan.change.Retired["fixture"] != sourceDigest(key) || len(plan.change.Keys) != 0 {
		t.Fatal("removal did not store only a digest")
	}
	legacy := plan.change
	legacy.Retired = nil
	legacy.Keys = map[string][]byte{"fixture": key}
	oversize := plan
	oversize.change = legacy
	oversize.change.Keys = map[string][]byte{"fixture": make([]byte, maxSourceState)}
	if _, err = c.applySource(dir, oversize); !systemops.Unchanged(err) {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(c.root, sourceIntent)); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	rows, err := c.sources()
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err = atomicAt(dir, sourceIntent, raw, 0600, c.owner); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(c.config, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = c.repairSources(ctx, dir, nil); err != nil {
		t.Fatal(err)
	}
	if raw, err := c.keyBytes("fixture"); err != nil || raw != nil {
		t.Fatal(raw, err)
	}
}

func TestCatalogSolverBacktracksAcrossParentsAndKeepsPolicy(t *testing.T) {
	c, _ := catalogFixture(t)
	manifest := func(id, version, signer string, deps map[string]any) Manifest {
		m := fixtureManifest(t)
		m["id"], m["version"], m["signer"], m["dependencies"] = id, version, signer, deps
		return m
	}
	entry := func(id, version, signer string, deps map[string]any) release {
		if deps == nil {
			deps = map[string]any{}
		}
		return release{manifest: manifest(id, version, signer, deps)}
	}
	idx := catalogIndex{modules: map[string][]release{
		"example":  {entry("example", "1.0.0", "fixture", map[string]any{"parent-a": ">=1.0.0", "parent-b": ">=1.0.0"})},
		"parent-a": {entry("parent-a", "1.0.0", "fixture", map[string]any{"shared": ">=1.0.0"})},
		"parent-b": {entry("parent-b", "1.0.0", "fixture", map[string]any{"shared": ">=2.0.0,<3.0.0"})},
		"shared":   {entry("shared", "3.0.0", "fixture", nil), entry("shared", "2.5.0", "different", nil), entry("shared", "2.1.0", "fixture", nil), entry("shared", "2.0.0", "fixture", nil), entry("shared", "0.9.0", "fixture", nil)},
	}}
	installed := Registry{"shared": manifest("shared", "1.0.0", "fixture", map[string]any{}), "existing": manifest("existing", "1.0.0", "fixture", map[string]any{"shared": "<=2.0.0"})}
	verify := func(want string) {
		t.Helper()
		chosen, order, _, err := c.solveCatalog(context.Background(), idx, installed, "example", "1.0.0")
		if err != nil || text(chosen["shared"].manifest, "version") != want {
			t.Fatal(order, chosen, err)
		}
	}
	verify("2.0.0") // Installed is too old, newest conflicts, foreign signer is refused, and 2.1 would break an existing dependent.
	idx.modules["parent-b"][0].manifest["dependencies"] = map[string]any{"shared": ">=1.0.0"}
	verify("") // Reuse the installed dependency where all parents permit it.
	idx.modules["parent-b"][0].manifest["dependencies"] = map[string]any{"shared": "<1.0.0"}
	idx.modules["parent-a"][0].manifest["dependencies"] = map[string]any{"shared": ">=0.9.0"}
	if _, _, _, err := c.solveCatalog(context.Background(), idx, installed, "example", "1.0.0"); err == nil {
		t.Fatal("downgrade accepted")
	}
	idx.modules["example"] = make([]release, catalogSearchBudget)
	if _, _, _, err := c.solveCatalog(context.Background(), idx, installed, "example", "1.0.0"); err == nil || !strings.Contains(err.Error(), "search limit") {
		t.Fatal(err)
	}
}

func TestHostedCatalogInstallReportsNativeCleanupAfterCommit(t *testing.T) {
	c, _, _ := installCatalogFixture(t, false)
	p := map[string]any{"target": "example", "version": "1.0.0"}
	fp := catalogPlanFingerprint(t, c, "module.catalog-install", p)
	activated := false
	c.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
		if strings.Join(argv, " ") == "systemctl daemon-reload" {
			activated = true
		}
		return nil, nil
	}
	c.mounts = func() ([]string, error) {
		if activated {
			return []string{filepath.Join(c.root, ".transaction")}, nil
		}
		return nil, nil
	}
	raw, err := c.executeCatalog(context.Background(), "module.catalog-install", p, fp, nil, func() error { return nil })
	if err != nil || !strings.Contains(string(raw), committedRecovery) {
		t.Fatal(string(raw), err)
	}
	state, err := c.loadTransaction()
	if err != nil || state == nil || !state.Committed {
		t.Fatal(state, err)
	}
	assertCatalogStageClean(t, c)
}

type DispatcherCatalog struct {
	Plan                 func(context.Context, string, map[string]any) (json.RawMessage, error)
	Execute              func(context.Context, string, map[string]any, string, *systemops.Reporter, func() error) (json.RawMessage, error)
	Query, Recover       func(context.Context, string) (json.RawMessage, error)
	Journal, Config, Key string
}

// InterruptedCatalogForDispatcher exposes the filesystem-backed test catalog to
// the dispatcher integration test without changing the installed paths.
func InterruptedCatalogForDispatcher(t *testing.T, legacy bool) DispatcherCatalog {
	t.Helper()
	c, _ := catalogFixture(t)
	params := servePendingRepository(t, &c)
	fixture := DispatcherCatalog{Plan: c.planCatalog, Execute: c.executeCatalog, Query: c.query, Recover: c.recoverCatalog,
		Journal: filepath.Join(c.root, sourceIntent), Config: c.config, Key: filepath.Join(c.keys, "pending.pem")}
	if legacy {
		plan, err := c.planSource(t.Context(), "module.source-add", params)
		if err != nil {
			t.Fatal(err)
		}
		change := plan.change
		raw, err := json.Marshal(map[string]any{"ID": change.ID, "Add": true, "Before": change.Before, "After": change.After, "Keys": change.Keys})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.Journal, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.Key, change.Keys["pending"], 0644); err != nil {
			t.Fatal(err)
		}
		return fixture
	}
	stop := errors.New("interrupted before config replacement")
	c.sourceBoundary = func(phase string) error {
		if phase == "key-written" {
			return stop
		}
		return nil
	}
	if _, err := executePlannedSource(t, c, "module.source-add", params); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	return fixture
}
