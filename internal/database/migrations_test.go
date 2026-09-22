package database

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"path/filepath"
	"testing"
)

func openTest(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "state.db")+"?_txlock=immediate&_busy_timeout=5000&_synchronous=FULL")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
func TestUpgradeIsAtomicAndPreservesLegacyData(t *testing.T) {
	db := openTest(t)
	if _, err := db.Exec("CREATE TABLE data(value TEXT);INSERT INTO data VALUES('kept')"); err != nil {
		t.Fatal(err)
	}
	base := []Migration{{"baseline", "CREATE TABLE IF NOT EXISTS data(value TEXT)"}}
	if err := Migrate(db, "test", base); err != nil {
		t.Fatal(err)
	}
	bad := append(append([]Migration{}, base...), Migration{"broken", "ALTER TABLE data ADD COLUMN label TEXT;INSERT INTO missing VALUES(1)"})
	if Migrate(db, "test", bad) == nil {
		t.Fatal("broken upgrade accepted")
	}
	var value string
	var count int
	if err := db.QueryRow("SELECT value FROM data").Scan(&value); err != nil || value != "kept" {
		t.Fatal(value, err)
	}
	db.QueryRow("SELECT count(*) FROM panasms_migrations").Scan(&count)
	if count != 1 {
		t.Fatal("failed upgrade advanced journal")
	}
	if _, err := db.Exec("SELECT label FROM data"); err == nil {
		t.Fatal("DDL escaped rollback")
	}
	good := append(append([]Migration{}, base...), Migration{"label", "ALTER TABLE data ADD COLUMN label TEXT DEFAULT 'old'"})
	for i := 0; i < 2; i++ {
		if err := Migrate(db, "test", good); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.QueryRow("SELECT label FROM data").Scan(&value); err != nil || value != "old" {
		t.Fatal(value, err)
	}
	if Migrate(db, "test", base) == nil {
		t.Fatal("downgrade accepted")
	}
	good[0].SQL += ";SELECT 1"
	if Migrate(db, "test", good) == nil {
		t.Fatal("modified migration accepted")
	}
	if Migrate(db, "other", good) == nil {
		t.Fatal("wrong database accepted")
	}
}
func TestRejectFutureLegacyCoreBeforeChanges(t *testing.T) {
	db := openTest(t)
	db.Exec("CREATE TABLE schema_version(version INTEGER PRIMARY KEY);INSERT INTO schema_version VALUES(2)")
	if Migrate(db, "core", []Migration{{"base", "CREATE TABLE should_not_exist(id INTEGER)"}}) == nil {
		t.Fatal("future schema accepted")
	}
	var count int
	db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name IN ('panasms_migrations','should_not_exist')").Scan(&count)
	if count != 0 {
		t.Fatal("failed validation mutated database")
	}
}
