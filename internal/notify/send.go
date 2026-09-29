package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	webpush "github.com/SherClockHolmes/webpush-go"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"time"
)

var ErrExpired = errors.New("delivery.subscriptionExpired")

func NewPushKeys() (string, string, error) { return webpush.GenerateVAPIDKeys() }
func SendEmail(ctx context.Context, c SMTP, to string, m Message) error {
	if !c.Enabled || to == "" {
		return errors.New("delivery.notConfigured")
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	cfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	if c.Security == "tls" {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return errors.New("delivery.connectionFailed")
	}
	defer conn.Close()
	deadline := time.Now().Add(20 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return errors.New("delivery.smtpFailed")
	}
	defer client.Close()
	if c.Security == "starttls" {
		if err = client.StartTLS(cfg); err != nil {
			return errors.New("delivery.tlsFailed")
		}
	}
	if c.Username != "" {
		if err = client.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return errors.New("delivery.authenticationFailed")
		}
	}
	if err = client.Mail(c.From); err != nil {
		return errors.New("delivery.smtpFailed")
	}
	if err = client.Rcpt(to); err != nil {
		return errors.New("delivery.recipientRejected")
	}
	w, err := client.Data()
	if err != nil {
		return errors.New("delivery.smtpFailed")
	}
	raw := "From: " + c.From + "\r\nTo: " + to + "\r\nSubject: " + mime.QEncoding.Encode("utf-8", m.Title) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + m.Body + "\r\n"
	if _, err = io.WriteString(w, raw); err != nil {
		return errors.New("delivery.smtpFailed")
	}
	if err = w.Close(); err != nil {
		return errors.New("delivery.smtpFailed")
	}
	client.Quit()
	return nil
}
func SendTelegram(ctx context.Context, c Config, chat string, m Message) error {
	if !c.TelegramEnabled || chat == "" {
		return errors.New("delivery.notConfigured")
	}
	raw, _ := json.Marshal(map[string]any{"chat_id": chat, "text": m.Title + "\n\n" + m.Body, "link_preview_options": map[string]bool{"is_disabled": true}})
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.telegram.org/bot"+c.TelegramToken+"/sendMessage", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("delivery.connectionFailed")
	}
	defer resp.Body.Close()
	var result struct {
		OK bool `json:"ok"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&result) != nil || !result.OK {
		return errors.New("delivery.telegramFailed")
	}
	return nil
}
func SendPush(ctx context.Context, c Config, sub Subscription, m Message) error {
	if c.Contact == "" || c.PrivateKey == "" {
		return errors.New("delivery.notConfigured")
	}
	if err := sub.Validate(); err != nil {
		return err
	}
	raw, _ := json.Marshal(m)
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := webpush.SendNotificationWithContext(ctx, raw, &webpush.Subscription{Endpoint: sub.Endpoint, Keys: webpush.Keys{Auth: sub.Keys.Auth, P256dh: sub.Keys.P256dh}}, &webpush.Options{HTTPClient: client, Subscriber: c.Contact, VAPIDPrivateKey: c.PrivateKey, VAPIDPublicKey: c.PublicKey, TTL: 3600})
	if err != nil {
		return errors.New("delivery.pushFailed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 || resp.StatusCode == 410 {
		return ErrExpired
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("delivery.pushFailed")
	}
	return nil
}
