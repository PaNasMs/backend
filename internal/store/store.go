package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	_ "github.com/mattn/go-sqlite3"
	"strconv"
	"strings"
	"time"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, e := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY);
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
 CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY,message TEXT NOT NULL,active INTEGER NOT NULL,created TEXT NOT NULL,updated TEXT NOT NULL);`)
	if e != nil {
		db.Close()
		return nil, e
	}
	return &Store{db}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func digest(t string) string  { h := sha256.Sum256([]byte(t)); return hex.EncodeToString(h[:]) }
func (s *Store) Session(user string) (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	token := hex.EncodeToString(b)
	_, e := s.db.Exec("DELETE FROM sessions WHERE expires <= ?", time.Now().Unix())
	if e != nil {
		return "", e
	}
	_, e = s.db.Exec("INSERT INTO sessions VALUES(?,?,?)", digest(token), user, time.Now().Add(8*time.Hour).Unix())
	return token, e
}
func (s *Store) User(token string) (string, error) {
	if len(token) != 64 {
		return "", errors.New("invalid session")
	}
	var u string
	e := s.db.QueryRow("SELECT username FROM sessions WHERE token=? AND expires>?", digest(token), time.Now().Unix()).Scan(&u)
	return u, e
}
func (s *Store) Revoke(token string) error {
	_, e := s.db.Exec("DELETE FROM sessions WHERE token=?", digest(token))
	return e
}

type DesktopTile struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	X    int    `json:"x"`
	Y    int    `json:"y"`
}
type Preferences struct {
	Language          string                   `json:"language"`
	Taskbar           *[]string                `json:"taskbar,omitempty"`
	DesktopLayouts    map[string][]DesktopTile `json:"desktopLayouts,omitempty"`
	SmartCrcBaselines map[string]uint64        `json:"smartCrcBaselines,omitempty"`
	Theme             string                   `json:"theme"`
	Layouts           map[string][]string      `json:"layouts"`
}

func DefaultPreferences() Preferences {
	return Preferences{Language: "en", Theme: "dark", Layouts: map[string][]string{}}
}
func (s *Store) Preferences(user string) (Preferences, error) {
	p := DefaultPreferences()
	var v string
	e := s.db.QueryRow("SELECT value FROM preferences WHERE username=?", user).Scan(&v)
	if errors.Is(e, sql.ErrNoRows) {
		return p, nil
	}
	if e != nil {
		return p, e
	}
	e = json.Unmarshal([]byte(v), &p)
	if p.Language == "" {
		p.Language = "en"
	}
	return p, e
}
func (s *Store) Save(user string, p Preferences) error {
	b, e := json.Marshal(p)
	if e != nil {
		return e
	}
	_, e = s.db.Exec("INSERT INTO preferences VALUES(?,?) ON CONFLICT(username) DO UPDATE SET value=excluded.value", user, string(b))
	return e
}

func (s *Store) RevokeUser(username string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE username=?", username)
	return err
}

func (s *Store) RecordMetrics(v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	minute := time.Now().Unix() / 60
	_, e = s.db.Exec("INSERT OR IGNORE INTO metric_history VALUES(?,?)", minute, string(b))
	if e != nil {
		return e
	}
	_, e = s.db.Exec("DELETE FROM metric_history WHERE minute < ?", minute-7*24*60)
	return e
}
func (s *Store) MetricsHistory(hours int) ([]json.RawMessage, error) {
	rows, e := s.db.Query("SELECT value FROM metric_history WHERE minute>=? ORDER BY minute", time.Now().Unix()/60-int64(hours*60))
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	data := []json.RawMessage{}
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		data = append(data, json.RawMessage(raw))
	}
	return data, rows.Err()
}

type Alert struct {
	Severity string `json:"severity"`
	ID       string `json:"id"`
	Message  string `json:"message"`
	Active   bool   `json:"active"`
	Created  string `json:"created"`
	Updated  string `json:"updated"`
}

func alertSeverity(id, message string) string {
	switch {
	case strings.HasPrefix(id, "job:"):
		if strings.Contains(message, "Cancelled") {
			return "warning"
		}
		return "error"
	case strings.HasPrefix(id, "update:result:"):
		if strings.Contains(message, "recovery-required") || strings.Contains(message, "failed") {
			return "error"
		}
		if strings.Contains(message, "rolled-back") {
			return "warning"
		}
		return "success"
	case strings.HasPrefix(id, "device:") && strings.Contains(message, "check storage."):
		return "warning"
	case strings.HasPrefix(message, "SMART: disk failure:"):
		return "error"
	case strings.HasPrefix(id, "smart:"), strings.HasPrefix(id, "heat:"), id == "cpu-hot", id == "system-full", id == "cooling-stale":
		return "warning"
	default:
		return "info"
	}
}
func (s *Store) Alert(id, message string, active bool) {
	now := time.Now().UTC().Format(time.RFC3339)
	if active {
		s.db.Exec("INSERT INTO alerts VALUES(?,?,1,?,?) ON CONFLICT(id) DO UPDATE SET message=excluded.message,active=1,updated=excluded.updated WHERE alerts.active=0 OR alerts.message!=excluded.message", id, message, now, now)
	} else {
		s.db.Exec("UPDATE alerts SET active=0,updated=? WHERE id=? AND active=1", now, id)
	}
}
func (s *Store) Inform(id, message string) {
	now := time.Now().UTC().Format(time.RFC3339)
	s.db.Exec("INSERT INTO alerts VALUES(?,?,0,?,?) ON CONFLICT(id) DO NOTHING", id, message, now, now)
}
func (s *Store) Alerts() ([]Alert, error) {
	rows, e := s.db.Query("SELECT id,message,active,created,updated FROM alerts ORDER BY active DESC,updated DESC LIMIT 200")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	data := []Alert{}
	for rows.Next() {
		var a Alert
		if e = rows.Scan(&a.ID, &a.Message, &a.Active, &a.Created, &a.Updated); e != nil {
			return nil, e
		}
		a.Severity = alertSeverity(a.ID, a.Message)
		data = append(data, a)
	}
	return data, rows.Err()
}
func (s *Store) PruneAlerts(before time.Time) {
	s.db.Exec("DELETE FROM alerts WHERE active=0 AND updated<?", before.UTC().Format(time.RFC3339))
	s.db.Exec("DELETE FROM dismissed_alerts WHERE id NOT IN (SELECT id FROM alerts)")
}

func alertRevision(a Alert) string { return a.Updated + ":" + strconv.FormatBool(a.Active) }
func (s *Store) VisibleAlerts(user string, alerts []Alert) ([]Alert, error) {
	rows, err := s.db.Query("SELECT id,revision FROM dismissed_alerts WHERE username=?", user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hidden := map[string]string{}
	for rows.Next() {
		var id, revision string
		if err := rows.Scan(&id, &revision); err != nil {
			return nil, err
		}
		hidden[id] = revision
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	visible := []Alert{}
	for _, a := range alerts {
		if hidden[a.ID] != alertRevision(a) {
			visible = append(visible, a)
		}
	}
	return visible, nil
}
func (s *Store) DismissResolvedAlerts(user string, alerts []Alert) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, a := range alerts {
		if !a.Active {
			if _, err = tx.Exec("INSERT INTO dismissed_alerts VALUES(?,?,?) ON CONFLICT(username,id) DO UPDATE SET revision=excluded.revision", user, a.ID, alertRevision(a)); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) WallpaperVersion(user string) (string, error) {
	var version string
	err := s.db.QueryRow("SELECT version FROM wallpapers WHERE username=?", user).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return version, err
}
func (s *Store) Wallpaper(user string) ([]byte, error) {
	var data []byte
	err := s.db.QueryRow("SELECT image FROM wallpapers WHERE username=?", user).Scan(&data)
	return data, err
}
func (s *Store) SaveWallpaper(user string, data []byte) (string, error) {
	if len(data) == 0 {
		_, err := s.db.Exec("DELETE FROM wallpapers WHERE username=?", user)
		return "", err
	}
	version := digest(string(data))
	_, err := s.db.Exec("INSERT INTO wallpapers VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET version=excluded.version,image=excluded.image", user, version, data)
	return version, err
}
