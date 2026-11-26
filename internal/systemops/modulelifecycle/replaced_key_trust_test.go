package modulelifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestWithdrawalReplayDoesNotTrustReplacement(t *testing.T) {
	s, _ := withdrawalPending(t)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(s.keys, "catalog.pem"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.recoverStartup(context.Background()); err != nil {
		return
	} // Refusing completion pending new approval is permitted.
	if _, err := readPublicKey(s.keys, "catalog", s.owner); err == nil {
		t.Fatal("completed withdrawal still trusts the unreviewed replacement publisher key")
	}
}
