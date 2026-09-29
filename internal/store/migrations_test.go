package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingInitializedCoreDatabaseDoesNotBecomeEmptyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Save("alice", Preferences{Language: "uk", Theme: "light"}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path + ".initialized"); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(path); err == nil || !strings.Contains(err.Error(), "restore the database") {
		t.Fatalf("missing core database was not rejected: %v", err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("empty core database was created: %v", err)
	}
}

func TestCorruptCoreDatabaseIsPreservedForRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	bad := []byte("not a SQLite database")
	if err = os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(path); err == nil {
		t.Fatal("corrupt core database was accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(bad) {
		t.Fatalf("corrupt database was replaced: %v", err)
	}
}

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
