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
 CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY,message TEXT NOT NULL,active INTEGER NOT NULL,created TEXT NOT NULL,updated TEXT NOT NULL);`}, {Name: "external-connections", SQL: `
CREATE TABLE external_providers(provider TEXT PRIMARY KEY,client_id TEXT NOT NULL,secret BLOB NOT NULL,enabled INTEGER NOT NULL,revision TEXT NOT NULL);
CREATE TABLE external_connections(id TEXT PRIMARY KEY,provider TEXT NOT NULL,subject TEXT NOT NULL,username TEXT NOT NULL,uid INTEGER NOT NULL,principal TEXT NOT NULL,email TEXT NOT NULL,name TEXT NOT NULL,created INTEGER NOT NULL,UNIQUE(provider,subject));
CREATE INDEX external_connection_owner ON external_connections(username);
`}, {Name: "external-grants", SQL: `
CREATE TABLE external_grants(id TEXT PRIMARY KEY,connection_id TEXT NOT NULL REFERENCES external_connections(id) ON DELETE CASCADE,consumer TEXT NOT NULL,capability TEXT NOT NULL,scope TEXT NOT NULL,revision TEXT NOT NULL,epoch TEXT NOT NULL,installation TEXT NOT NULL,secret BLOB NOT NULL,status TEXT NOT NULL,created INTEGER NOT NULL,UNIQUE(connection_id,consumer,capability));
`}, {Name: "notification-delivery", SQL: `
CREATE TABLE notification_secrets(id TEXT PRIMARY KEY,value BLOB NOT NULL);
CREATE TABLE notification_recipients(username TEXT PRIMARY KEY,uid INTEGER NOT NULL,principal TEXT NOT NULL,since INTEGER NOT NULL,value TEXT NOT NULL);
CREATE TABLE notification_devices(username TEXT NOT NULL,id TEXT NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(username,id));
CREATE TABLE notification_seen(username TEXT NOT NULL,id TEXT NOT NULL,state TEXT NOT NULL,updated INTEGER NOT NULL,PRIMARY KEY(username,id));
CREATE TABLE notification_delivery(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,event_key TEXT NOT NULL,channel TEXT NOT NULL,device TEXT NOT NULL,payload BLOB NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL,next_attempt INTEGER NOT NULL,created INTEGER NOT NULL,error TEXT NOT NULL,UNIQUE(username,event_key,channel,device));
CREATE INDEX notification_delivery_pending ON notification_delivery(status,next_attempt);
`}, {Name: "telegram-link", SQL: `
CREATE TABLE telegram_pair(username TEXT PRIMARY KEY,uid INTEGER NOT NULL,principal TEXT NOT NULL,bot TEXT NOT NULL,code TEXT UNIQUE NOT NULL,expires INTEGER NOT NULL,chat TEXT NOT NULL,name TEXT NOT NULL);
CREATE TABLE telegram_links(username TEXT PRIMARY KEY,uid INTEGER NOT NULL,principal TEXT NOT NULL,bot TEXT NOT NULL,chat TEXT NOT NULL,name TEXT NOT NULL);
`}, {Name: "external-account-authorizations", SQL: `
CREATE TABLE external_account_authorizations(connection_id TEXT NOT NULL REFERENCES external_connections(id) ON DELETE CASCADE,scope TEXT NOT NULL,revision TEXT NOT NULL,epoch TEXT NOT NULL,secret BLOB NOT NULL,status TEXT NOT NULL,PRIMARY KEY(connection_id,scope));
`}}
