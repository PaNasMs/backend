package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"panasms.local/backend/internal/notify"
	"strings"
	"testing"
	"time"
)

func TestTelegramRelayRequiresSignedFreshProof(t *testing.T) {
	s := testServer(t)
	token := "123456:abcdefghijklmnopqrstuvwx"
	c := notify.Config{TelegramEnabled: true, TelegramToken: token}
	if err := s.Store.SaveNotificationSecret("config", c); err != nil {
		t.Fatal(err)
	}
	p, err := s.Store.StartTelegramPair("alice", 1000, "p", telegramBotKey(token))
	if err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{"code":%q,"chatId":"12345","name":"Alice","timestamp":%d}`, p.Code, time.Now().Unix())
	for _, signed := range []bool{false, true} {
		r := httptest.NewRequest("POST", "/api/v1/notification-telegram-relay", strings.NewReader(raw))
		if signed {
			mac := hmac.New(sha256.New, []byte(token))
			mac.Write([]byte("panasms-telegram-link-v1\n" + raw))
			r.Header.Set("X-PaNasMs-Telegram-Signature", hex.EncodeToString(mac.Sum(nil)))
		}
		w := httptest.NewRecorder()
		s.telegramLinkRelay(w, r)
		expected := 403
		if signed {
			expected = 204
		}
		if w.Code != expected {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	l, _ := s.Store.TelegramLink("alice", 1000, "p", telegramBotKey(token))
	if l.ChatID != "" {
		t.Fatal("relay linked without NAS confirmation")
	}
	p, err = s.Store.TelegramPair("alice", 1000, "p", telegramBotKey(token))
	if err != nil || !p.Ready || p.Name != "Alice" {
		t.Fatal(p, err)
	}
}
