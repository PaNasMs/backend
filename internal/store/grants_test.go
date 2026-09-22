package store

import (
	"bytes"
	"encoding/json"
	"golang.org/x/oauth2"
	"path/filepath"
	"testing"
	"time"
)

func TestGrantVaultIsolationAndCascade(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := ExternalConnection{ID: "c", Provider: "google", Subject: "sub", Username: "alice", UID: 1000, Principal: "p"}
	if err = s.LinkExternal(c); err != nil {
		t.Fatal(err)
	}
	g := ExternalGrant{ID: "g", ConnectionID: "c", Consumer: "cloud-sync", Capability: "google-drive", Scope: "drive", Revision: "r", Epoch: "e", Installation: "i", Token: &oauth2.Token{AccessToken: "private-access", RefreshToken: "private-refresh", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	if err = s.SaveExternalGrant(g); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	s.db.QueryRow("SELECT secret FROM external_grants").Scan(&ciphertext)
	if bytes.Contains(ciphertext, []byte("private")) {
		t.Fatal("plaintext tokens")
	}
	restored, err := s.ExternalGrant("g")
	if err != nil || restored.Token.RefreshToken != g.Token.RefreshToken {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(restored)
	if bytes.Contains(raw, []byte("private")) {
		t.Fatal("token in metadata")
	}
	other, err := s.ExternalGrants("bob", 1000, "p")
	if err != nil || len(other) != 0 {
		t.Fatal("cross-user metadata", err)
	}
	other, _ = s.ExternalGrants("alice", 1000, "new")
	if len(other) != 0 {
		t.Fatal("recreated owner metadata")
	}
	s.db.Exec("UPDATE external_grants SET consumer='files'")
	if _, err = s.ExternalGrant("g"); err == nil {
		t.Fatal("AAD not bound to consumer")
	}
	s.db.Exec("UPDATE external_grants SET consumer='cloud-sync'")
	if err = s.SetGrantStatus("g", "reconnect_required"); err != nil {
		t.Fatal(err)
	}
	restored, err = s.ExternalGrant("g")
	if err != nil || restored.Token != nil {
		t.Fatal("invalidated token retained", err)
	}
	if err = s.UnlinkExternal("alice", "c"); err != nil {
		t.Fatal(err)
	}
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM external_grants").Scan(&count)
	if count != 0 {
		t.Fatal("unlink left grants")
	}
}
