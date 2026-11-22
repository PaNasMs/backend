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
	"path/filepath"
	"testing"
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
		supplyPEM    bool
	}{
		{"edited-source", false, true},
		{"matching-rows", true, true},
		{"matching-rows-without-key", true, false},
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
			fp := catalogPlanFingerprint(t, c, action, params)
			if _, err := c.executeCatalog(ctx, action, params, fp, nil, func() error { return nil }); !errors.Is(err, stopped) {
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
			if tc.supplyPEM {
				independentPEM = read(filepath.Join(c.keys, "fixture.pem"))
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
