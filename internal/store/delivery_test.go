package store

import (
	"bytes"
	"panasms.local/backend/internal/notify"
	"path/filepath"
	"testing"
	"time"
)

func deliveryStore(t *testing.T) *Store {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestDeliverySecretsEncryptedAndBound(t *testing.T) {
	s := deliveryStore(t)
	c := notify.Config{TelegramToken: "secret-value"}
	if e := s.SaveNotificationSecret("config", c); e != nil {
		t.Fatal(e)
	}
	var raw []byte
	s.db.QueryRow("SELECT value FROM notification_secrets WHERE id='config'").Scan(&raw)
	if bytes.Contains(raw, []byte("secret-value")) {
		t.Fatal("plaintext secret")
	}
	got, e := s.DeliveryConfig()
	if e != nil || got.TelegramToken != c.TelegramToken {
		t.Fatal(got, e)
	}
	s.db.Exec("INSERT INTO notification_secrets VALUES('other',?)", raw)
	if s.NotificationSecret("other", &got) == nil {
		t.Fatal("ciphertext not context-bound")
	}
}
func TestNotificationTransitionsAndNoBackfill(t *testing.T) {
	s := deliveryStore(t)
	r := Recipient{Username: "alice", Since: time.Now().Unix(), Preferences: notify.Defaults()}
	r.Preferences.Enabled = true
	e := notify.Event{ID: "disk", Revision: "1", Severity: "warning"}
	old := time.Now().Add(-time.Hour)
	if err := s.ObserveNotification(r, e, old); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Deliveries("alice", false)
	if len(d) != 0 {
		t.Fatal("backfilled history")
	}
	e.Revision = "2"
	s.ObserveNotification(r, e, time.Now())
	d, _ = s.Deliveries("alice", false)
	if len(d) != 0 {
		t.Fatal("repeated stable condition")
	}
	e.Severity = "critical"
	s.ObserveNotification(r, e, time.Now())
	s.ObserveNotification(r, e, time.Now())
	d, _ = s.Deliveries("alice", false)
	if len(d) != 1 || d[0].Channel != "telegram" {
		t.Fatal(d)
	}
	e.Resolved = true
	s.ObserveNotification(r, e, time.Now())
	e.Resolved = false
	e.Revision = "3"
	s.ObserveNotification(r, e, time.Now())
	d, _ = s.Deliveries("alice", false)
	if len(d) != 2 {
		t.Fatal(d)
	}
}
func TestDeliveryPersistsAndSettingsCancelQueue(t *testing.T) {
	s := deliveryStore(t)
	r := Recipient{Username: "alice", UID: 1000, Principal: "one", Preferences: notify.Defaults()}
	r.Preferences.Enabled = true
	if err := s.SaveRecipient(r); err != nil {
		t.Fatal(err)
	}
	if err := s.QueueTest("alice", "email", ""); err != nil {
		t.Fatal(err)
	}
	items, err := s.Deliveries("", true)
	if err != nil || len(items) != 1 {
		t.Fatal(items, err)
	}
	if err = s.FinishDelivery(items[0], "pending", "delivery.connectionFailed"); err != nil {
		t.Fatal(err)
	}
	due, _ := s.Deliveries("", true)
	if len(due) != 0 {
		t.Fatal("retry has no backoff")
	}
	if err = s.SaveRecipient(r); err != nil {
		t.Fatal(err)
	}
	items, _ = s.Deliveries("alice", false)
	if items[0].Status != "cancelled" {
		t.Fatal(items)
	}
}
func TestRecreatedAccountLosesDeliveryDestinations(t *testing.T) {
	s := deliveryStore(t)
	s.BindAccount("alice", 1000, "old")
	s.SaveRecipient(Recipient{Username: "alice", UID: 1000, Principal: "old", Preferences: notify.Defaults()})
	s.SaveNotificationSecret("push:alice:abc", map[string]string{"endpoint": "secret"})
	s.QueueTest("alice", "email", "")
	if err := s.BindAccount("alice", 1000, "new"); err != nil {
		t.Fatal(err)
	}
	r, _ := s.Recipient("alice")
	if r.Principal != "" {
		t.Fatal("inherited recipient")
	}
	items, _ := s.Deliveries("alice", false)
	if len(items) != 0 {
		t.Fatal("inherited deliveries")
	}
	var raw map[string]string
	if s.NotificationSecret("push:alice:abc", &raw) == nil {
		t.Fatal("retained old push secret")
	}
}

func TestNotificationFanoutIsIndependentAndDeduplicated(t *testing.T) {
	s := deliveryStore(t)
	r := Recipient{Username: "alice", Since: time.Now().Unix(), Preferences: notify.Defaults()}
	r.Preferences.Enabled = true
	r.Preferences.Routes["critical"] = notify.Channels{"email", "telegram", "push"}
	e := notify.Event{ID: "disk", Revision: "1", Severity: "critical"}
	for i := 0; i < 2; i++ {
		if err := s.ObserveNotification(r, e, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	deliveries, err := s.Deliveries("alice", false)
	if err != nil || len(deliveries) != 3 {
		t.Fatal(deliveries, err)
	}
	channels := map[string]bool{}
	for _, d := range deliveries {
		channels[d.Channel] = true
		status := "sent"
		if d.Channel == "email" {
			status = "pending"
		}
		if err = s.FinishDelivery(d, status, ""); err != nil {
			t.Fatal(err)
		}
	}
	if len(channels) != 3 {
		t.Fatal(channels)
	}
	deliveries, _ = s.Deliveries("alice", false)
	for _, d := range deliveries {
		if d.Channel != "email" && d.Status != "sent" {
			t.Fatal("one channel changed another", d)
		}
	}
	r.Preferences.Routes["critical"] = notify.Channels{}
	e.ID = "other-disk"
	if err = s.ObserveNotification(r, e, time.Now()); err != nil {
		t.Fatal(err)
	}
	deliveries, _ = s.Deliveries("alice", false)
	if len(deliveries) != 3 {
		t.Fatal("empty selection sent externally")
	}
}
