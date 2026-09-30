package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// Account authorization outlives an individual module installation or grant.
func accountAuthorization(connection, scope string) ExternalGrant {
	sum := sha256.Sum256([]byte(connection + "\x00" + scope))
	return ExternalGrant{ID: hex.EncodeToString(sum[:]), ConnectionID: connection, Scope: scope, Consumer: "@account", Capability: "authorization", Status: "active"}
}
func (s *Store) SaveAccountAuthorization(source ExternalGrant) error {
	g := accountAuthorization(source.ConnectionID, source.Scope)
	g.Revision, g.Epoch, g.Token = source.Revision, source.Epoch, source.Token
	if g.Token == nil || g.Token.AccessToken == "" {
		return errors.New("missing account authorization")
	}
	raw, err := s.sealGrant(g)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO external_account_authorizations(connection_id,scope,revision,epoch,secret,status) VALUES(?,?,?,?,?,'active') ON CONFLICT(connection_id,scope) DO UPDATE SET revision=excluded.revision,epoch=excluded.epoch,secret=excluded.secret,status='active'`, g.ConnectionID, g.Scope, g.Revision, g.Epoch, raw)
	return err
}
func (s *Store) AccountAuthorization(connection, scope string) (ExternalGrant, error) {
	g := accountAuthorization(connection, scope)
	var raw []byte
	err := s.db.QueryRow(`SELECT revision,epoch,secret,status FROM external_account_authorizations WHERE connection_id=? AND scope=?`, connection, scope).Scan(&g.Revision, &g.Epoch, &raw, &g.Status)
	if err != nil || g.Status != "active" {
		return g, err
	}
	box, err := s.externalCipher(false)
	if err != nil {
		return g, err
	}
	if len(raw) < box.NonceSize() {
		return g, errors.New("invalid account authorization")
	}
	plain, err := box.Open(nil, raw[:box.NonceSize()], raw[box.NonceSize():], g.aad())
	if err != nil {
		return g, err
	}
	err = json.Unmarshal(plain, &g.Token)
	return g, err
}
func (s *Store) InvalidateAccountAuthorization(connection, scope string) error {
	_, err := s.db.Exec(`UPDATE external_account_authorizations SET status='reconnect_required',secret=X'' WHERE connection_id=? AND scope=?`, connection, scope)
	return err
}
