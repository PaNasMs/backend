package store

import (
	"golang.org/x/oauth2"
	"testing"
)

func TestAccountAuthorizationEncryptedAndBoundToScope(t *testing.T) {
	s, err := Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.LinkExternal(ExternalConnection{ID: "account", Provider: "google", Subject: "subject", Username: "alice", UID: 1000, Principal: "principal"}); err != nil {
		t.Fatal(err)
	}
	g := ExternalGrant{ConnectionID: "account", Scope: "files", Revision: "v1", Epoch: "epoch", Token: &oauth2.Token{AccessToken: "secret-access", RefreshToken: "secret-refresh"}}
	if err = s.SaveAccountAuthorization(g); err != nil {
		t.Fatal(err)
	}
	a, err := s.AccountAuthorization("account", "files")
	if err != nil || a.Token.RefreshToken != "secret-refresh" {
		t.Fatal("authorization round trip", err)
	}
	s.db.Exec("UPDATE external_account_authorizations SET scope='other'")
	if _, err = s.AccountAuthorization("account", "other"); err == nil {
		t.Fatal("scope tampering accepted")
	}
	s.db.Exec("UPDATE external_account_authorizations SET scope='files'")
	if err = s.InvalidateAccountAuthorization("account", "files"); err != nil {
		t.Fatal(err)
	}
	a, err = s.AccountAuthorization("account", "files")
	if err != nil || a.Status != "reconnect_required" || a.Token != nil {
		t.Fatal("revoked token retained")
	}
}
