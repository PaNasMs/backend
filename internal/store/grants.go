package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"time"
)

type ExternalGrant struct {
	ID           string        `json:"id"`
	ConnectionID string        `json:"connectionId"`
	Consumer     string        `json:"consumer"`
	Capability   string        `json:"capability"`
	Scope        string        `json:"scope"`
	Status       string        `json:"status"`
	Created      int64         `json:"created"`
	Revision     string        `json:"-"`
	Epoch        string        `json:"-"`
	Installation string        `json:"-"`
	Token        *oauth2.Token `json:"-"`
}

func (s *Store) ExternalConnection(id string) (ExternalConnection, error) {
	var c ExternalConnection
	err := s.db.QueryRow("SELECT id,provider,subject,username,uid,principal,email,name,created FROM external_connections WHERE id=?", id).Scan(&c.ID, &c.Provider, &c.Subject, &c.Username, &c.UID, &c.Principal, &c.Email, &c.Name, &c.Created)
	return c, err
}
func (g ExternalGrant) aad() []byte {
	raw, _ := json.Marshal([]string{g.ID, g.ConnectionID, g.Consumer, g.Capability, g.Scope, g.Revision, g.Epoch, g.Installation})
	return raw
}
func (s *Store) sealGrant(g ExternalGrant) ([]byte, error) {
	box, err := s.externalCipher(true)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(g.Token)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, box.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return box.Seal(nonce, nonce, raw, g.aad()), nil
}
func (s *Store) SaveExternalGrant(g ExternalGrant) error {
	raw, err := s.sealGrant(g)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM external_grants WHERE connection_id=? AND consumer=? AND capability=?", g.ConnectionID, g.Consumer, g.Capability); err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO external_grants VALUES(?,?,?,?,?,?,?,?,?,?,?)", g.ID, g.ConnectionID, g.Consumer, g.Capability, g.Scope, g.Revision, g.Epoch, g.Installation, raw, "active", time.Now().Unix())
	if err != nil {
		return err
	}
	return tx.Commit()
}

const grantColumns = "id,connection_id,consumer,capability,scope,revision,epoch,installation,status,created"

func scanGrant(row interface{ Scan(...any) error }) (ExternalGrant, error) {
	var g ExternalGrant
	err := row.Scan(&g.ID, &g.ConnectionID, &g.Consumer, &g.Capability, &g.Scope, &g.Revision, &g.Epoch, &g.Installation, &g.Status, &g.Created)
	return g, err
}
func (s *Store) ExternalGrants(user string, uid int, principal string) ([]ExternalGrant, error) {
	rows, err := s.db.Query("SELECT "+grantColumns+" FROM external_grants WHERE connection_id IN (SELECT id FROM external_connections WHERE username=? AND uid=? AND principal=?) ORDER BY created", user, uid, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []ExternalGrant{}
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, g)
	}
	return result, rows.Err()
}
func (s *Store) ExternalGrant(id string) (ExternalGrant, error) {
	g, err := scanGrant(s.db.QueryRow("SELECT "+grantColumns+" FROM external_grants WHERE id=?", id))
	if err != nil {
		return g, err
	}
	if g.Status != "active" {
		return g, nil
	}
	var raw []byte
	if err = s.db.QueryRow("SELECT secret FROM external_grants WHERE id=?", id).Scan(&raw); err != nil {
		return g, err
	}
	box, err := s.externalCipher(false)
	if err != nil {
		return g, err
	}
	if len(raw) < box.NonceSize() {
		return g, errors.New("invalid grant storage")
	}
	plain, err := box.Open(nil, raw[:box.NonceSize()], raw[box.NonceSize():], g.aad())
	if err != nil {
		return g, err
	}
	var token oauth2.Token
	if err = json.Unmarshal(plain, &token); err != nil {
		return g, err
	}
	g.Token = &token
	return g, nil
}
func (s *Store) UpdateExternalGrant(g ExternalGrant) error {
	raw, err := s.sealGrant(g)
	if err != nil {
		return err
	}
	result, err := s.db.Exec("UPDATE external_grants SET secret=? WHERE id=? AND status='active'", raw, g.ID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return sql.ErrNoRows
	}
	return err
}
func (s *Store) SetGrantStatus(id, status string) error {
	_, err := s.db.Exec("UPDATE external_grants SET status=?,secret=X'' WHERE id=?", status, id)
	return err
}
func (s *Store) DeleteExternalGrant(id string) error {
	_, err := s.db.Exec("DELETE FROM external_grants WHERE id=?", id)
	return err
}
