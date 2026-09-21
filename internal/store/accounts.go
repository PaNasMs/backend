package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

type SessionInfo struct {
	ID      string `json:"id"`
	User    string `json:"user"`
	Address string `json:"address"`
	Device  string `json:"device"`
	Created int64  `json:"created"`
	Expires int64  `json:"expires"`
	Current bool   `json:"current"`
	Kind    string `json:"kind"`
}

func (s *Store) SessionDetails(token string, uid int, epoch, address, device string) error {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	if len(device) > 512 {
		device = device[:512]
	}
	if len(address) > 128 {
		address = address[:128]
	}
	_, err := s.db.Exec("INSERT OR REPLACE INTO session_details(token,id,uid,epoch,address,device,created) VALUES(?,?,?,?,?,?,?)", digest(token), hex.EncodeToString(b), uid, epoch, address, device, time.Now().Unix())
	return err
}
func (s *Store) SessionMatches(token string, uid int, epoch string) bool {
	var storedUID int
	var storedEpoch string
	err := s.db.QueryRow("SELECT uid,epoch FROM session_details WHERE token=?", digest(token)).Scan(&storedUID, &storedEpoch)
	return err == nil && storedUID == uid && storedEpoch == epoch
}
func (s *Store) Sessions(user, token string) ([]SessionInfo, error) {
	rows, err := s.db.Query(`SELECT d.id,s.username,d.address,d.device,d.created,s.expires,s.token=? FROM sessions s JOIN session_details d ON d.token=s.token WHERE s.username=? AND s.expires>? ORDER BY d.created DESC`, digest(token), user, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []SessionInfo{}
	for rows.Next() {
		var item SessionInfo
		item.Kind = "panel"
		if err = rows.Scan(&item.ID, &item.User, &item.Address, &item.Device, &item.Created, &item.Expires, &item.Current); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
func (s *Store) EndSession(user, id string) error {
	result, err := s.db.Exec("DELETE FROM sessions WHERE username=? AND token IN(SELECT token FROM session_details WHERE id=?)", user, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("Session has already ended")
	}
	return nil
}
func (s *Store) Audit(user, actor, action, result string) {
	s.db.Exec("INSERT INTO account_audit(username,actor,action,result,created) VALUES(?,?,?,?,?)", user, actor, action, result, time.Now().UTC().Format(time.RFC3339))
	s.db.Exec("DELETE FROM account_audit WHERE id NOT IN(SELECT id FROM account_audit ORDER BY id DESC LIMIT 10000)")
}
func (s *Store) History(user string) ([]map[string]string, error) {
	rows, err := s.db.Query("SELECT username,actor,action,result,created FROM account_audit WHERE username=? ORDER BY id DESC LIMIT 100", user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []map[string]string{}
	for rows.Next() {
		var u, a, action, state, created string
		if err = rows.Scan(&u, &a, &action, &state, &created); err != nil {
			return nil, err
		}
		result = append(result, map[string]string{"user": u, "actor": a, "action": action, "result": state, "created": created})
	}
	return result, rows.Err()
}

// Preserve existing profiles on first upgrade, but never inherit a recreated account's data.
func (s *Store) BindAccount(user string, uid int, principal string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldUID int
	var oldPrincipal string
	err = tx.QueryRow("SELECT uid,principal FROM account_bindings WHERE username=?", user).Scan(&oldUID, &oldPrincipal)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	changed := err == nil && (oldUID != uid || oldPrincipal != principal) || errors.Is(err, sql.ErrNoRows) && principal != ""
	if changed {
		for _, table := range []string{"sessions", "preferences", "wallpapers", "avatars", "dismissed_alerts", "account_audit"} {
			if _, err = tx.Exec("DELETE FROM "+table+" WHERE username=?", user); err != nil {
				return err
			}
		}
	}
	if _, err = tx.Exec("INSERT INTO account_bindings(username,uid,principal) VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET uid=excluded.uid,principal=excluded.principal", user, uid, principal); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AuditJob(id, user, actor, action, result, created string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row, err := tx.Exec("INSERT OR IGNORE INTO account_audit_jobs(id) VALUES(?)", id)
	if err != nil {
		return err
	}
	count, err := row.RowsAffected()
	if err != nil {
		return err
	}
	if count > 0 {
		if _, err = tx.Exec("INSERT INTO account_audit(username,actor,action,result,created) VALUES(?,?,?,?,?)", user, actor, action, result, created); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) PruneSessions(user string, uid int, epoch string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE username=? AND token NOT IN(SELECT token FROM session_details WHERE uid=? AND epoch=?)", user, uid, epoch)
	return err
}
