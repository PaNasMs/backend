package store

import (
	"path/filepath"
	"testing"
)

func TestAccountSessionIsolationAndRecreation(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Save("alice", Preferences{Language: "uk", Theme: "light"}); err != nil {
		t.Fatal(err)
	}
	if err = s.BindAccount("alice", 1000, ""); err != nil {
		t.Fatal(err)
	}
	p, _ := s.Preferences("alice")
	if p.Language != "uk" {
		t.Fatal("upgrade lost preferences")
	}
	token, _ := s.Session("alice")
	if err = s.SessionDetails(token, 1000, "one", "127.0.0.1", "browser"); err != nil {
		t.Fatal(err)
	}
	if !s.SessionMatches(token, 1000, "one") || s.SessionMatches(token, 1001, "one") || s.SessionMatches(token, 1000, "two") {
		t.Fatal("session identity not bound")
	}
	sessions, err := s.Sessions("alice", token)
	if err != nil || len(sessions) != 1 || !sessions[0].Current || sessions[0].ID == token {
		t.Fatal(sessions, err)
	}
	if err = s.EndSession("bob", sessions[0].ID); err == nil {
		t.Fatal("cross-user session deletion")
	}
	others, _ := s.Sessions("bob", token)
	if len(others) != 0 {
		t.Fatal("cross-user disclosure")
	}
	if err = s.BindAccount("alice", 1000, "recreated"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.User(token); err == nil {
		t.Fatal("recreated account inherited session")
	}
	p, _ = s.Preferences("alice")
	if p.Language != "en" {
		t.Fatal("recreated account inherited profile")
	}
	token, _ = s.Session("alice")
	s.SessionDetails(token, 1000, "two", "", "browser")
	sessions, _ = s.Sessions("alice", token)
	if err = s.EndSession("alice", sessions[0].ID); err != nil {
		t.Fatal(err)
	}
	if s.SessionMatches(token, 1000, "two") {
		t.Fatal("session metadata not cascaded")
	}
}
