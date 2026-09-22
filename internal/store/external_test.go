package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExternalSecretsAndIdentityIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	config := ExternalConfig{ClientID: "test-client", ClientSecret: "not-a-real-secret", Enabled: true, Revision: "1"}
	if err = s.SaveExternalConfig("google", config); err != nil {
		t.Fatal(err)
	}
	restored, err := s.ExternalConfig("google")
	if err != nil || restored != config {
		t.Fatal(restored, err)
	}
	var encrypted []byte
	s.db.QueryRow("SELECT secret FROM external_providers").Scan(&encrypted)
	if bytes.Contains(encrypted, []byte(config.ClientSecret)) {
		t.Fatal("plaintext secret")
	}
	mode, err := os.Stat(path + ".external.key")
	if err != nil || mode.Mode().Perm() != 0600 {
		t.Fatal("key permissions", err)
	}
	encrypted[len(encrypted)-1] ^= 1
	s.db.Exec("UPDATE external_providers SET secret=?", encrypted)
	if _, err = s.ExternalConfig("google"); err == nil {
		t.Fatal("modified ciphertext accepted")
	}
	c := ExternalConnection{ID: "1", Provider: "google", Subject: "subject", Username: "alice", UID: 1000, Principal: "original", Email: "user@example.test"}
	if err = s.BindAccount("alice", 1000, "original"); err != nil {
		t.Fatal(err)
	}
	if err = s.LinkExternal(c); err != nil {
		t.Fatal(err)
	}
	c.ID = "2"
	c.Username = "bob"
	if err = s.LinkExternal(c); err == nil {
		t.Fatal("Google identity linked twice")
	}
	for _, id := range []struct {
		user      string
		uid       int
		principal string
	}{{"bob", 1000, "original"}, {"alice", 1001, "original"}, {"alice", 1000, "recreated"}} {
		connections, err := s.ExternalConnections(id.user, id.uid, id.principal)
		if err != nil || len(connections) != 0 {
			t.Fatal(connections, err)
		}
	}
	token, _ := s.Session("alice")
	if err = s.UnlinkExternal("bob", "1"); err == nil {
		t.Fatal("another user unlinked account")
	}
	if err = s.UnlinkExternal("alice", "1"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.User(token); err == nil {
		t.Fatal("sessions not revoked")
	}
	c.ID = "3"
	c.Username = "alice"
	if err = s.LinkExternal(c); err != nil {
		t.Fatal(err)
	}
	if err = s.BindAccount("alice", 1000, "recreated"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ExternalOwner("google", "subject"); err == nil {
		t.Fatal("recreated account inherited link")
	}
}
func TestMissingExternalKeyFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.SaveExternalConfig("google", ExternalConfig{ClientSecret: "secret"}); err != nil {
		t.Fatal(err)
	}
	os.Remove(path + ".external.key")
	if _, err = s.ExternalConfig("google"); err == nil {
		t.Fatal("missing key accepted")
	}
}
