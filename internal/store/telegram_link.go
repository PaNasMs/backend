package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

type TelegramLink struct {
	ChatID    string `json:"-"`
	Name      string `json:"name"`
	Bot       string `json:"-"`
	UID       int    `json:"-"`
	Principal string `json:"-"`
}
type TelegramPair struct {
	Code    string `json:"code,omitempty"`
	Name    string `json:"name,omitempty"`
	Expires int64  `json:"expires"`
	Ready   bool   `json:"ready"`
}

func (s *Store) StartTelegramPair(user string, uid int, principal, bot string) (TelegramPair, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return TelegramPair{}, err
	}
	code := hex.EncodeToString(b)
	expiry := time.Now().Add(10 * time.Minute).Unix()
	_, err := s.db.Exec(`INSERT INTO telegram_pair VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET uid=excluded.uid,principal=excluded.principal,bot=excluded.bot,code=excluded.code,expires=excluded.expires,chat='',name=''`, user, uid, principal, bot, digest(code), expiry, "", "")
	return TelegramPair{Code: code, Expires: expiry}, err
}
func (s *Store) TelegramPair(user string, uid int, principal, bot string) (TelegramPair, error) {
	var p TelegramPair
	var chat string
	err := s.db.QueryRow(`SELECT expires,chat,name FROM telegram_pair WHERE username=? AND uid=? AND principal=? AND bot=? AND expires>?`, user, uid, principal, bot, time.Now().Unix()).Scan(&p.Expires, &chat, &p.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	p.Ready = chat != ""
	return p, err
}
func (s *Store) OfferTelegramPair(code, bot, chat, name string) error {
	result, err := s.db.Exec(`UPDATE telegram_pair SET chat=?,name=? WHERE code=? AND bot=? AND expires>? AND (chat='' OR chat=?)`, chat, name, digest(code), bot, time.Now().Unix(), chat)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return errors.New("delivery.linkExpired")
	}
	return err
}
func (s *Store) ConfirmTelegramPair(user string, uid int, principal, bot string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO telegram_links SELECT username,uid,principal,bot,chat,name FROM telegram_pair WHERE username=? AND uid=? AND principal=? AND bot=? AND expires>? AND chat<>'' ON CONFLICT(username) DO UPDATE SET uid=excluded.uid,principal=excluded.principal,bot=excluded.bot,chat=excluded.chat,name=excluded.name`, user, uid, principal, bot, time.Now().Unix())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("delivery.linkExpired")
	}
	if _, err = tx.Exec("DELETE FROM telegram_pair WHERE username=?", user); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) TelegramLink(user string, uid int, principal, bot string) (TelegramLink, error) {
	var l TelegramLink
	err := s.db.QueryRow(`SELECT chat,name FROM telegram_links WHERE username=? AND uid=? AND principal=? AND bot=?`, user, uid, principal, bot).Scan(&l.ChatID, &l.Name)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return l, err
}
func (s *Store) UnlinkTelegram(user string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"telegram_pair", "telegram_links"} {
		if _, err = tx.Exec("DELETE FROM "+table+" WHERE username=?", user); err != nil {
			return err
		}
	}
	_, err = tx.Exec("UPDATE notification_delivery SET status='cancelled',error='delivery.settingsChanged' WHERE username=? AND channel='telegram' AND status='pending'", user)
	if err != nil {
		return err
	}
	return tx.Commit()
}
