package modulelifecycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"panasms.local/backend/internal/systemops"
)

func TestFreshSourceAddRejectsDifferentPublisherKeyBeforeJournal(t *testing.T) {
	s, files, candidate := catalogFixture(t) // Map-backed fetch; no HTTP server or transport.
	signCatalogFixture(t, files, candidate, []any{})

	trusted, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if trusted.Equal(candidate.Public()) {
		t.Fatal("fixture needs distinct publisher keys")
	}
	der, err := x509.MarshalPKIXPublicKey(trusted)
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	rows := mustJSON(t, []Manifest{officialSource(), {
		"id": "existing-repo", "url": "https://example.org/existing/", "signers": []any{"catalog"}, "official": false,
	}})
	config := filepath.Dir(s.keys)
	original := map[string][]byte{filepath.Join(s.keys, "catalog.pem"): key, filepath.Join(config, sourceFile): rows}
	for path, data := range original {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	// No prior review, fingerprint, or pending intent: reject at fresh preparation.
	plan, err := s.prepareSource(t.Context(), "module.source-add", map[string]any{"url": fixtureBase})
	var rejected *systemops.Rejected
	if plan != nil || !errors.As(err, &rejected) || rejected.Message != "This publisher ID already uses another public key" {
		t.Fatalf("expected publisher key conflict and no plan; got plan=%v, err=%v", plan, err)
	}
	if _, err := os.Lstat(filepath.Join(config, sourceIntent)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected no pending source intent; lstat: %v", err)
	}
	for path, want := range original {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s did not retain its original bytes (read error: %v)", path, err)
		}
	}
}
