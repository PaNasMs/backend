package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSessionsAndPreferences(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	token, e := s.Session("alice")
	if e != nil {
		t.Fatal(e)
	}
	u, e := s.User(token)
	if e != nil || u != "alice" {
		t.Fatalf("session: %s %v", u, e)
	}
	var stored string
	s.db.QueryRow("SELECT token FROM sessions").Scan(&stored)
	if stored == token {
		t.Fatal("raw session token stored")
	}
	if _, e = s.User("invalid"); e == nil {
		t.Fatal("accepted invalid session")
	}
	if e = s.Revoke(token); e != nil {
		t.Fatal(e)
	}
	if _, e = s.User(token); e == nil {
		t.Fatal("revoked session accepted")
	}
	token, _ = s.Session("alice")
	s.db.Exec("UPDATE sessions SET expires=?", time.Now().Add(-time.Second).Unix())
	if _, e = s.User(token); e == nil {
		t.Fatal("expired session accepted")
	}
	p := Preferences{SmartCrcBaselines: map[string]uint64{"WD:serial": 7}, Theme: "light", Layouts: map[string][]string{"mobile": {"cpu", "memory"}}}
	if e = s.Save("alice", p); e != nil {
		t.Fatal(e)
	}
	got, e := s.Preferences("alice")
	if e != nil || got.Theme != "light" || got.SmartCrcBaselines["WD:serial"] != 7 {
		t.Fatal(got, e)
	}
	other, _ := s.Preferences("bob")
	if other.Theme != "dark" || len(other.SmartCrcBaselines) != 0 {
		t.Fatal("cross-user preferences")
	}
}

func TestRevokeUserKeepsOtherAccounts(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, _ := s.Session("alice")
	b, _ := s.Session("alice")
	other, _ := s.Session("bob")
	if err := s.RevokeUser("alice"); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{a, b} {
		if _, err := s.User(token); err == nil {
			t.Fatal("old user session remains valid")
		}
	}
	if name, err := s.User(other); err != nil || name != "bob" {
		t.Fatal("unrelated session revoked")
	}
}

func TestClearAlertHistoryKeepsActive(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Alert("active", "warning", true)
	s.Alert("old", "resolved", true)
	s.Alert("old", "resolved", false)
	history, _ := s.Alerts()
	if err := s.DismissResolvedAlerts("alice", history); err != nil {
		t.Fatal(err)
	}
	alerts, err := s.Alerts()
	if err != nil || len(alerts) != 2 {
		t.Fatalf("%+v %v", alerts, err)
	}
	s.PruneAlerts(time.Now().Add(-time.Hour))
	visible, err := s.VisibleAlerts("alice", alerts)
	if err != nil || len(visible) != 1 || visible[0].ID != "active" {
		t.Fatal(visible, err)
	}
	visible, err = s.VisibleAlerts("bob", alerts)
	if err != nil || len(visible) != 2 {
		t.Fatal("other user's history changed", visible, err)
	}
	s.Alert("old", "new warning", true)
	alerts, _ = s.Alerts()
	visible, err = s.VisibleAlerts("alice", alerts)
	if err != nil || len(visible) != 2 {
		t.Fatal("new alert hidden", visible, err)
	}
}

func TestDismissAcceptedCRCDoesNotHideNewWarnings(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Alert("smart:disk", "raw warning", true)
	alerts, _ := s.Alerts()
	alerts[0].Active = false
	if err := s.DismissResolvedAlerts("alice", alerts); err != nil {
		t.Fatal(err)
	}
	visible, err := s.VisibleAlerts("alice", alerts)
	if err != nil || len(visible) != 0 {
		t.Fatal(visible, err)
	}
	visible, err = s.VisibleAlerts("bob", alerts)
	if err != nil || len(visible) != 1 {
		t.Fatal("another user affected", visible, err)
	}
	alerts[0].Active = true
	visible, err = s.VisibleAlerts("alice", alerts)
	if err != nil || len(visible) != 1 {
		t.Fatal("new warning hidden", visible, err)
	}
	raw, _ := s.Alerts()
	if len(raw) != 1 || !raw[0].Active {
		t.Fatal("raw health changed", raw)
	}
}

func TestTaskbarPersistsEmptyAndOrderPerUser(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, ids := range [][]string{{"files", "users"}, {}} {
		if err := s.Save("alice", Preferences{Taskbar: &ids}); err != nil {
			t.Fatal(err)
		}
		got, err := s.Preferences("alice")
		if err != nil || got.Taskbar == nil || len(*got.Taskbar) != len(ids) {
			t.Fatal(got, err)
		}
		for i, id := range ids {
			if (*got.Taskbar)[i] != id {
				t.Fatal("order lost")
			}
		}
	}
	other, err := s.Preferences("bob")
	if err != nil || other.Taskbar != nil {
		t.Fatal("cross-user taskbar", err)
	}
}

func TestLanguageDefaultPersistenceAndIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "languages.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := s.Preferences("new-user"); err != nil || p.Language != "en" {
		t.Fatal(p, err)
	}
	if _, err := s.db.Exec(`INSERT INTO preferences(username,value) VALUES(?,?)`, "legacy", `{"theme":"light"}`); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Preferences("legacy"); err != nil || p.Language != "en" || p.Theme != "light" {
		t.Fatal(p, err)
	}
	for user, lang := range map[string]string{"alice": "uk", "bob": "ru"} {
		p := DefaultPreferences()
		p.Language = lang
		if err := s.Save(user, p); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for user, lang := range map[string]string{"alice": "uk", "bob": "ru", "charlie": "en"} {
		if p, err := s.Preferences(user); err != nil || p.Language != lang {
			t.Fatal(user, p, err)
		}
	}
}
