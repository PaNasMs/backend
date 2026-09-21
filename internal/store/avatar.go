package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
)

func (s *Store) Avatar(user string) (string, []byte, error) {
	var version string
	var image []byte
	err := s.db.QueryRow("SELECT version,image FROM avatars WHERE username=?", user).Scan(&version, &image)
	if err == sql.ErrNoRows {
		return "", nil, nil
	}
	return version, image, err
}
func (s *Store) SaveAvatar(user string, image []byte) (string, error) {
	if image == nil {
		_, err := s.db.Exec("DELETE FROM avatars WHERE username=?", user)
		return "", err
	}
	sum := sha256.Sum256(image)
	version := hex.EncodeToString(sum[:])
	_, err := s.db.Exec("INSERT INTO avatars VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET version=excluded.version,image=excluded.image", user, version, image)
	return version, err
}
