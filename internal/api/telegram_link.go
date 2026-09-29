package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/notify"
	"regexp"
	"time"
)

func telegramBotKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func (s *Server) telegramLink(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	s.deliveryMu.Lock()
	defer s.deliveryMu.Unlock()
	c, err := s.Store.DeliveryConfig()
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	bot := telegramBotKey(c.TelegramToken)
	if r.Method == "DELETE" {
		if err = s.Store.UnlinkTelegram(id.Username); err != nil {
			fail(w, 503, "delivery.unavailable")
			return
		}
		w.WriteHeader(204)
		return
	}
	if r.Method == "POST" {
		if !c.TelegramEnabled {
			fail(w, 409, "delivery.notConfigured")
			return
		}
		if !s.permit("telegram-link:" + id.Username) {
			fail(w, 429, "delivery.rateLimited")
			return
		}
		var input struct {
			Action string `json:"action"`
		}
		if !decode(w, r, &input) {
			return
		}
		if input.Action == "start" {
			p, e := s.Store.StartTelegramPair(id.Username, id.UID, id.Principal, bot)
			if e != nil {
				fail(w, 503, "delivery.unavailable")
				return
			}
			jsonResponse(w, 200, p)
			return
		}
		if input.Action != "confirm" {
			fail(w, 400, "delivery.linkExpired")
			return
		}
		if err = s.Store.ConfirmTelegramPair(id.Username, id.UID, id.Principal, bot); err != nil {
			fail(w, 409, "delivery.linkExpired")
			return
		}
		s.Store.Audit(id.Username, id.Username, "notifications.telegram-link", "succeeded")
	}
	l, err := s.Store.TelegramLink(id.Username, id.UID, id.Principal, bot)
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	p, err := s.Store.TelegramPair(id.Username, id.UID, id.Principal, bot)
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	jsonResponse(w, 200, map[string]any{"linked": l.ChatID != "", "name": l.Name, "pending": p, "enabled": c.TelegramEnabled})
}
func (s *Server) telegramLinkRelay(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(raw) > 4096 {
		fail(w, 400, "Invalid payload")
		return
	}
	c, err := s.Store.DeliveryConfig()
	if err != nil || !c.TelegramEnabled || c.TelegramToken == "" {
		fail(w, 403, "Relay unavailable")
		return
	}
	mac := hmac.New(sha256.New, []byte(c.TelegramToken))
	mac.Write([]byte("panasms-telegram-link-v1\n"))
	mac.Write(raw)
	signature, err := hex.DecodeString(r.Header.Get("X-PaNasMs-Telegram-Signature"))
	if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
		fail(w, 403, "Invalid signature")
		return
	}
	var input struct {
		Code      string `json:"code"`
		ChatID    string `json:"chatId"`
		Name      string `json:"name"`
		Timestamp int64  `json:"timestamp"`
	}
	if json.Unmarshal(raw, &input) != nil || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(input.Code) || !regexp.MustCompile(`^[1-9][0-9]{0,19}$`).MatchString(input.ChatID) || len(input.Name) > 256 || input.Name == "" || input.Timestamp < time.Now().Unix()-60 || input.Timestamp > time.Now().Unix()+60 {
		fail(w, 400, "Invalid payload")
		return
	}
	s.deliveryMu.Lock()
	defer s.deliveryMu.Unlock()
	if err = s.Store.OfferTelegramPair(input.Code, telegramBotKey(c.TelegramToken), input.ChatID, input.Name); err != nil {
		fail(w, 409, "delivery.linkExpired")
		return
	}
	w.WriteHeader(204)
}
func (s *Server) telegramTest(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	if !s.permit("notification-test:" + id.Username) {
		fail(w, 429, "delivery.rateLimited")
		return
	}
	c, err := s.Store.DeliveryConfig()
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	l, err := s.Store.TelegramLink(id.Username, id.UID, id.Principal, telegramBotKey(c.TelegramToken))
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	if l.ChatID == "" {
		fail(w, 409, "delivery.linkFirst")
		return
	}
	p, err := s.Store.Preferences(id.Username)
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	if err = notify.SendTelegram(ctx, c, l.ChatID, (notify.Event{Kind: "test", Severity: "info"}).Message(p.Language)); err != nil {
		fail(w, 502, err.Error())
		return
	}
	w.WriteHeader(204)
}
