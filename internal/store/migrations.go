package store

import "panasms.local/backend/internal/database"

var migrations = []database.Migration{{Name: "core-baseline", SQL: `CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY);
 INSERT OR IGNORE INTO schema_version VALUES(1);
 CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, username TEXT NOT NULL, expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS account_bindings(username TEXT PRIMARY KEY,uid INTEGER NOT NULL,principal TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS session_details(token TEXT PRIMARY KEY REFERENCES sessions(token) ON DELETE CASCADE,id TEXT UNIQUE NOT NULL,uid INTEGER NOT NULL,epoch TEXT NOT NULL,address TEXT NOT NULL,device TEXT NOT NULL,created INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS account_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,result TEXT NOT NULL,created TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS account_audit_jobs(id TEXT PRIMARY KEY);
 CREATE TABLE IF NOT EXISTS avatars(username TEXT PRIMARY KEY,version TEXT NOT NULL,image BLOB NOT NULL);
 CREATE TABLE IF NOT EXISTS wallpapers(username TEXT PRIMARY KEY,version TEXT NOT NULL,image BLOB NOT NULL);
 CREATE TABLE IF NOT EXISTS preferences(username TEXT PRIMARY KEY, value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS metric_history(minute INTEGER PRIMARY KEY,value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS dismissed_alerts(username TEXT NOT NULL,id TEXT NOT NULL,revision TEXT NOT NULL,PRIMARY KEY(username,id));
 CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY,message TEXT NOT NULL,active INTEGER NOT NULL,created TEXT NOT NULL,updated TEXT NOT NULL);`}}
