package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"panasms.local/backend/internal/notify"
	"time"
)

type Recipient struct {
	Username    string             `json:"-"`
	UID         int                `json:"-"`
	Principal   string             `json:"-"`
	Since       int64              `json:"-"`
	Preferences notify.Preferences `json:"preferences"`
}
type Delivery struct {
	ID       int64        `json:"id"`
	User     string       `json:"-"`
	Channel  string       `json:"channel"`
	Device   string       `json:"-"`
	Event    notify.Event `json:"event"`
	Attempts int          `json:"attempts"`
	Status   string       `json:"status"`
	Error    string       `json:"error,omitempty"`
	Created  int64        `json:"created"`
}

func (s *Store) NotificationSecret(key string, value any) error {
	var raw []byte
	err := s.db.QueryRow("SELECT value FROM notification_secrets WHERE id=?", key).Scan(&raw)
	if err != nil {
		return err
	}
	box, err := s.externalCipher(false)
	if err != nil {
		return err
	}
	if len(raw) < box.NonceSize() {
		return errors.New("invalid notification secret")
	}
	plain, err := box.Open(nil, raw[:box.NonceSize()], raw[box.NonceSize():], []byte("notifications:"+key))
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, value)
}
func (s *Store) SaveNotificationSecret(key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	box, err := s.externalCipher(true)
	if err != nil {
		return err
	}
	nonce := make([]byte, box.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	sealed := box.Seal(nonce, nonce, raw, []byte("notifications:"+key))
	_, err = s.db.Exec("INSERT INTO notification_secrets VALUES(?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value", key, sealed)
	return err
}
func (s *Store) DeliveryConfig() (notify.Config, error) {
	c := notify.Config{}
	c.SMTP.Port = 587
	c.SMTP.Security = "starttls"
	err := s.NotificationSecret("config", &c)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return c, err
}
func (s *Store) Recipient(user string) (Recipient, error) {
	r := Recipient{Username: user, Preferences: notify.Defaults()}
	var raw string
	err := s.db.QueryRow("SELECT uid,principal,since,value FROM notification_recipients WHERE username=?", user).Scan(&r.UID, &r.Principal, &r.Since, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return r, nil
	}
	if err == nil {
		err = json.Unmarshal([]byte(raw), &r.Preferences)
	}
	return r, err
}
func (s *Store) SaveRecipient(r Recipient) error {
	raw, err := json.Marshal(r.Preferences)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec("INSERT INTO notification_recipients VALUES(?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET uid=excluded.uid,principal=excluded.principal,since=excluded.since,value=excluded.value", r.Username, r.UID, r.Principal, time.Now().Unix(), raw)
	if err != nil {
		return err
	}
	_, err = tx.Exec("UPDATE notification_delivery SET status='cancelled',error='delivery.settingsChanged' WHERE username=? AND status='pending'", r.Username)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Recipients() ([]Recipient, error) {
	rows, err := s.db.Query("SELECT username,uid,principal,since,value FROM notification_recipients")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Recipient{}
	for rows.Next() {
		var r Recipient
		var raw string
		if err = rows.Scan(&r.Username, &r.UID, &r.Principal, &r.Since, &raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &r.Preferences); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
func (s *Store) SavePush(user string, sub notify.Subscription) (string, error) {
	id := digest(sub.Endpoint)
	if err := s.SaveNotificationSecret("push:"+user+":"+id, sub); err != nil {
		return "", err
	}
	_, err := s.db.Exec("INSERT INTO notification_devices VALUES(?,?,?) ON CONFLICT(username,id) DO UPDATE SET created=excluded.created", user, id, time.Now().Unix())
	return id, err
}
func (s *Store) PushDevices(user string) ([]string, error) {
	rows, err := s.db.Query("SELECT id FROM notification_devices WHERE username=? ORDER BY created DESC", user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (s *Store) RemovePush(user, id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM notification_devices WHERE username=? AND id=?", user, id); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM notification_secrets WHERE id=?", "push:"+user+":"+id); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) ObserveNotification(r Recipient, e notify.Event, stamp time.Time) error {
	state := e.Severity
	if e.Resolved {
		state = "resolved"
	}
	channels := r.Preferences.Routes[e.Severity]
	if e.Resolved {
		channels = r.Preferences.Routes["info"]
	}
	destinations := map[string][]string{}
	for _, channel := range channels {
		devices := []string{""}
		if channel == "push" {
			var err error
			devices, err = s.PushDevices(r.Username)
			if err != nil {
				return err
			}
			if len(devices) == 0 {
				devices = []string{""}
			}
		}
		destinations[channel] = devices
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old string
	err = tx.QueryRow("SELECT state FROM notification_seen WHERE username=? AND id=?", r.Username, e.ID).Scan(&old)
	fresh := errors.Is(err, sql.ErrNoRows)
	if err != nil && !fresh {
		return err
	}
	if !fresh && old == state {
		return nil
	}
	if _, err = tx.Exec("INSERT INTO notification_seen VALUES(?,?,?,?) ON CONFLICT(username,id) DO UPDATE SET state=excluded.state,updated=excluded.updated", r.Username, e.ID, state, time.Now().Unix()); err != nil {
		return err
	}
	if r.Preferences.Enabled && stamp.Unix() >= r.Since && !(fresh && e.Resolved) {
		for channel, devices := range destinations {
			for _, device := range devices {
				if _, err = tx.Exec("INSERT OR IGNORE INTO notification_delivery(username,event_key,channel,device,payload,status,attempts,next_attempt,created,error) VALUES(?,?,?,?,?,'pending',0,?,?, '')", r.Username, e.ID+":"+e.Revision+":"+state, channel, device, raw, time.Now().Unix(), time.Now().Unix()); err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}
func (s *Store) QueueTest(user, channel, device string) error {
	e := notify.Event{ID: "test", Severity: "info", Kind: "test", Route: "/profile/notifications"}
	raw, _ := json.Marshal(e)
	_, err := s.db.Exec("INSERT INTO notification_delivery(username,event_key,channel,device,payload,status,attempts,next_attempt,created,error) VALUES(?,?,?,?,?,'pending',0,?,?, '')", user, "test:"+time.Now().Format(time.RFC3339Nano), channel, device, raw, time.Now().Unix(), time.Now().Unix())
	return err
}
func (s *Store) Deliveries(user string, pending bool) ([]Delivery, error) {
	query := "SELECT id,username,channel,device,payload,attempts,status,error,created FROM notification_delivery WHERE username=? ORDER BY id DESC LIMIT 30"
	arg := any(user)
	if pending {
		query = "SELECT id,username,channel,device,payload,attempts,status,error,created FROM notification_delivery WHERE status='pending' AND next_attempt<=? ORDER BY id LIMIT 20"
		arg = time.Now().Unix()
	}
	rows, err := s.db.Query(query, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Delivery{}
	for rows.Next() {
		var d Delivery
		var raw []byte
		if err = rows.Scan(&d.ID, &d.User, &d.Channel, &d.Device, &raw, &d.Attempts, &d.Status, &d.Error, &d.Created); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &d.Event); err != nil {
			return nil, err
		}
		result = append(result, d)
	}
	return result, rows.Err()
}
func (s *Store) FinishDelivery(d Delivery, status, reason string) error {
	next := time.Now().Add(time.Duration(1<<min(d.Attempts, 6)) * time.Minute).Unix()
	_, err := s.db.Exec("UPDATE notification_delivery SET status=?,error=?,attempts=attempts+1,next_attempt=? WHERE id=?", status, reason, next, d.ID)
	return err
}
func (s *Store) PruneDeliveries() {
	s.db.Exec("UPDATE notification_delivery SET status='failed',error='delivery.expired' WHERE status='pending' AND created<?", time.Now().Add(-24*time.Hour).Unix())
	s.db.Exec("DELETE FROM notification_delivery WHERE status!='pending' AND created<?", time.Now().Add(-30*24*time.Hour).Unix())
	s.db.Exec("DELETE FROM notification_seen WHERE updated<? AND id NOT IN (SELECT id FROM alerts)", time.Now().Add(-30*24*time.Hour).Unix())
}

func (s *Store) RetryDelivery(user string, id int64) error {
	result, err := s.db.Exec("UPDATE notification_delivery SET status='pending',attempts=0,next_attempt=?,created=?,error='' WHERE id=? AND username=? AND status='failed'", time.Now().Unix(), time.Now().Unix(), id, user)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return errors.New("delivery.notRetryable")
	}
	return err
}
