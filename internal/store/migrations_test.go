package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestLegacyCoreUpgradeRetainsUserState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(migrations[0].SQL); err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`INSERT INTO preferences VALUES('alice','{"language":"uk","theme":"light"}');INSERT INTO alerts VALUES('old','Keep history',1,'now','now')`)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	prefs, err := s.Preferences("alice")
	if err != nil || prefs.Language != "uk" || prefs.Theme != "light" {
		t.Fatal(prefs, err)
	}
	var count int
	if err = s.db.QueryRow("SELECT count(*) FROM alerts WHERE id='old'").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if err = s.db.QueryRow("SELECT count(*) FROM panasms_migrations WHERE component='core'").Scan(&count); err != nil || count != len(migrations) {
		t.Fatal(count, err)
	}
}
