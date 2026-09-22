package management

import "panasms.local/backend/internal/database"

var migrations = []database.Migration{{Name: "jobs-baseline", SQL: `CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, username TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL, stage TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL, result TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS hidden_jobs(id TEXT PRIMARY KEY);
 CREATE TABLE IF NOT EXISTS job_reviews(id TEXT PRIMARY KEY, checked TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS job_context(id TEXT PRIMARY KEY, context TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS job_recovery(id TEXT PRIMARY KEY, report TEXT NOT NULL, checked TEXT NOT NULL);`}}
