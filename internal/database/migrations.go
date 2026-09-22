package database

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
)

type Migration struct{ Name, SQL string }

// All upgrades share one SQLite transaction: a failed migration must leave the
// previous schema and version intact. Callers use _txlock=immediate.
func Migrate(db *sql.DB, component string, migrations []Migration) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS panasms_migrations(component TEXT NOT NULL,version INTEGER NOT NULL,name TEXT NOT NULL,checksum TEXT NOT NULL,applied_at TEXT NOT NULL,PRIMARY KEY(component,version))`)
	if err != nil {
		return err
	}
	rows, err := tx.Query("SELECT component,version,name,checksum FROM panasms_migrations ORDER BY version")
	if err != nil {
		return err
	}
	applied := 0
	for rows.Next() {
		var owner, name, checksum string
		var version int
		if err = rows.Scan(&owner, &version, &name, &checksum); err != nil {
			rows.Close()
			return err
		}
		if owner != component || version != applied+1 || version > len(migrations) {
			rows.Close()
			return fmt.Errorf("incompatible %s database migration history; restore a compatible backup", component)
		}
		migration := migrations[version-1]
		if name != migration.Name || checksum != fmt.Sprintf("%x", sha256.Sum256([]byte(migration.SQL))) {
			rows.Close()
			return fmt.Errorf("%s migration %d has changed; restore compatible software", component, version)
		}
		applied = version
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// The original core used this single-row marker before the migration journal.
	if component == "core" && applied == 0 {
		var exists int
		if err = tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_version'").Scan(&exists); err != nil {
			return err
		}
		if exists != 0 {
			var count, version int
			if err = tx.QueryRow("SELECT count(*),COALESCE(max(version),0) FROM schema_version").Scan(&count, &version); err != nil {
				return err
			}
			if count != 1 || version != 1 {
				return fmt.Errorf("unsupported legacy core schema; restore a compatible backup")
			}
		}
	}
	for i := applied; i < len(migrations); i++ {
		migration := migrations[i]
		if _, err = tx.Exec(migration.SQL); err != nil {
			return fmt.Errorf("%s migration %d: %w", component, i+1, err)
		}
		if _, err = tx.Exec("INSERT INTO panasms_migrations VALUES(?,?,?,?,datetime('now'))", component, i+1, migration.Name, fmt.Sprintf("%x", sha256.Sum256([]byte(migration.SQL)))); err != nil {
			return err
		}
	}
	return tx.Commit()
}
