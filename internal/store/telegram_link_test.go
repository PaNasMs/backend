package store

import "testing"

func TestTelegramLinkLifecycle(t *testing.T) {
	s, err := Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err := s.StartTelegramPair("alice", 1000, "principal", "bot")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.OfferTelegramPair(p.Code, "other", "123", "Name"); err == nil {
		t.Fatal("wrong bot accepted")
	}
	if err = s.OfferTelegramPair(p.Code, "bot", "123", "Name"); err != nil {
		t.Fatal(err)
	}
	if err = s.OfferTelegramPair(p.Code, "bot", "456", "Other"); err == nil {
		t.Fatal("candidate overwritten")
	}
	if err = s.ConfirmTelegramPair("alice", 1001, "principal", "bot"); err == nil {
		t.Fatal("wrong UID accepted")
	}
	if err = s.ConfirmTelegramPair("alice", 1000, "principal", "bot"); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfirmTelegramPair("alice", 1000, "principal", "bot"); err == nil {
		t.Fatal("code reused")
	}
	l, err := s.TelegramLink("alice", 1000, "principal", "bot")
	if err != nil || l.ChatID != "123" || l.Name != "Name" {
		t.Fatal(l, err)
	}
	l, err = s.TelegramLink("alice", 1000, "new-principal", "bot")
	if err != nil || l.ChatID != "" {
		t.Fatal("account recreation leaked link", l, err)
	}
	if err = s.UnlinkTelegram("alice"); err != nil {
		t.Fatal(err)
	}
	l, _ = s.TelegramLink("alice", 1000, "principal", "bot")
	if l.ChatID != "" {
		t.Fatal("unlink failed")
	}
	p, _ = s.StartTelegramPair("alice", 1000, "principal", "bot")
	s.db.Exec("UPDATE telegram_pair SET expires=0")
	if s.OfferTelegramPair(p.Code, "bot", "123", "Name") == nil {
		t.Fatal("expired code accepted")
	}
}
