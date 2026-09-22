package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type ExternalConfig struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"-"`
	Enabled      bool   `json:"enabled"`
	Revision     string `json:"-"`
}
type ExternalConnection struct {
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	Subject   string `json:"-"`
	Username  string `json:"-"`
	UID       int    `json:"-"`
	Principal string `json:"-"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Created   int64  `json:"created"`
}

func (s *Store) externalCipher(create bool) (cipher.AEAD, error) {
	s.secretMu.Lock()
	defer s.secretMu.Unlock()
	raw, err := os.ReadFile(s.keyPath)
	if os.IsNotExist(err) && create {
		raw = make([]byte, 32)
		if _, err = rand.Read(raw); err != nil {
			return nil, err
		}
		f, e := os.OpenFile(s.keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if os.IsExist(e) {
			raw, err = os.ReadFile(s.keyPath)
		} else if e != nil {
			return nil, e
		} else {
			_, err = f.Write(raw)
			if err == nil {
				err = f.Sync()
			}
			f.Close()
			if err == nil {
				folder, e := os.Open(filepath.Dir(s.keyPath))
				if e != nil {
					return nil, e
				}
				err = folder.Sync()
				folder.Close()
			}
		}
	}
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func (s *Store) ExternalConfig(provider string) (ExternalConfig, error) {
	var config ExternalConfig
	var raw []byte
	err := s.db.QueryRow("SELECT client_id,secret,enabled,revision FROM external_providers WHERE provider=?", provider).Scan(&config.ClientID, &raw, &config.Enabled, &config.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return config, nil
	}
	if err != nil {
		return config, err
	}
	box, err := s.externalCipher(false)
	if err != nil {
		return config, err
	}
	if len(raw) < box.NonceSize() {
		return config, errors.New("invalid credential storage")
	}
	plain, err := box.Open(nil, raw[:box.NonceSize()], raw[box.NonceSize():], []byte(provider))
	config.ClientSecret = string(plain)
	return config, err
}
func (s *Store) SaveExternalConfig(provider string, config ExternalConfig) error {
	box, err := s.externalCipher(true)
	if err != nil {
		return err
	}
	nonce := make([]byte, box.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	sealed := box.Seal(nonce, nonce, []byte(config.ClientSecret), []byte(provider))
	_, err = s.db.Exec("INSERT INTO external_providers VALUES(?,?,?,?,?) ON CONFLICT(provider) DO UPDATE SET client_id=excluded.client_id,secret=excluded.secret,enabled=excluded.enabled,revision=excluded.revision", provider, config.ClientID, sealed, config.Enabled, config.Revision)
	return err
}
func (s *Store) LinkExternal(c ExternalConnection) error {
	_, err := s.db.Exec("INSERT INTO external_connections(id,provider,subject,username,uid,principal,email,name,created) VALUES(?,?,?,?,?,?,?,?,?)", c.ID, c.Provider, c.Subject, c.Username, c.UID, c.Principal, c.Email, c.Name, time.Now().Unix())
	return err
}
func (s *Store) ExternalConnections(user string, uid int, principal string) ([]ExternalConnection, error) {
	rows, err := s.db.Query("SELECT id,provider,email,name,created FROM external_connections WHERE username=? AND uid=? AND principal=? ORDER BY created", user, uid, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []ExternalConnection{}
	for rows.Next() {
		var c ExternalConnection
		if err = rows.Scan(&c.ID, &c.Provider, &c.Email, &c.Name, &c.Created); err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}
func (s *Store) ExternalOwner(provider, subject string) (ExternalConnection, error) {
	var c ExternalConnection
	err := s.db.QueryRow("SELECT id,username,uid,principal,email,name FROM external_connections WHERE provider=? AND subject=?", provider, subject).Scan(&c.ID, &c.Username, &c.UID, &c.Principal, &c.Email, &c.Name)
	return c, err
}
func (s *Store) UnlinkExternal(user, id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec("DELETE FROM external_connections WHERE username=? AND id=?", user, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	if _, err = tx.Exec("DELETE FROM sessions WHERE username=?", user); err != nil {
		return err
	}
	return tx.Commit()
}
