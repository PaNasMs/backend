package database

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/mattn/go-sqlite3"
)

func TestMigrationCrashProcess(t *testing.T) {
	path := os.Getenv("PANASMS_TEST_MIGRATION_DB")
	if path == "" {
		return
	}
	sql.Register("crash-test", &sqlite3.SQLiteDriver{ConnectHook: func(c *sqlite3.SQLiteConn) error {
		return c.RegisterFunc("crash_now", func() int { os.Exit(73); return 0 }, false)
	}})
	db, err := sql.Open("crash-test", path+"?_txlock=immediate&_journal_mode=WAL&_synchronous=FULL")
	if err != nil {
		t.Fatal(err)
	}
	err = Migrate(db, "test", []Migration{{"baseline", "CREATE TABLE IF NOT EXISTS data(value TEXT)"}, {"crash", "ALTER TABLE data ADD COLUMN partial TEXT;UPDATE data SET value='damaged';SELECT crash_now()"}})
	t.Fatalf("crash point was not reached: %v", err)
}

func TestProcessCrashRollsBackMigrationAndData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite3", path+"?_txlock=immediate&_journal_mode=WAL&_synchronous=FULL")
	if err != nil {
		t.Fatal(err)
	}
	base := []Migration{{"baseline", "CREATE TABLE IF NOT EXISTS data(value TEXT)"}}
	if err = Migrate(db, "test", base); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO data VALUES('kept')"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMigrationCrashProcess$")
	cmd.Env = append(os.Environ(), "PANASMS_TEST_MIGRATION_DB="+path)
	err = cmd.Run()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
		t.Fatalf("unexpected child exit: %v", err)
	}
	db, err = sql.Open("sqlite3", path+"?_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = Migrate(db, "test", base); err != nil {
		t.Fatal(err)
	}
	var value string
	if err = db.QueryRow("SELECT value FROM data").Scan(&value); err != nil || value != "kept" {
		t.Fatal(value, err)
	}
	if _, err = db.Exec("SELECT partial FROM data"); err == nil {
		t.Fatal("uncommitted schema survived crash")
	}
}
