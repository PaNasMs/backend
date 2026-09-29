package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/mail"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/management"
	"panasms.local/backend/internal/notify"
	"panasms.local/backend/internal/store"
	"strings"
	"time"
)

func (s *Server) deliverySettings(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	if id.Role != "admin" {
		fail(w, 403, "Administrator permissions required")
		return
	}
	s.deliveryMu.Lock()
	defer s.deliveryMu.Unlock()
	c, err := s.Store.DeliveryConfig()
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	if r.Method == "PUT" {
		var input notify.Config
		if !decode(w, r, &input) {
			return
		}
		input.PrivateKey = c.PrivateKey
		input.PublicKey = c.PublicKey
		if input.SMTP.Password == "" && input.SMTP.Host == c.SMTP.Host && input.SMTP.Username == c.SMTP.Username {
			input.SMTP.Password = c.SMTP.Password
		}
		if input.TelegramToken == "" {
			input.TelegramToken = c.TelegramToken
		}
		if err = input.Validate(); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if input.PrivateKey == "" {
			input.PrivateKey, input.PublicKey, err = notify.NewPushKeys()
			if err != nil {
				fail(w, 500, "delivery.unavailable")
				return
			}
		}
		if err = s.Store.SaveNotificationSecret("config", input); err != nil {
			fail(w, 503, "delivery.unavailable")
			return
		}
		c = input
		s.Store.Audit(id.Username, id.Username, "notifications.settings", "succeeded")
	}
	password, token := c.SMTP.Password != "", c.TelegramToken != ""
	c.SMTP.Password = ""
	c.TelegramToken = ""
	c.PrivateKey = ""
	jsonResponse(w, 200, map[string]any{"config": c, "passwordConfigured": password, "tokenConfigured": token})
}
func (s *Server) deliveryProfile(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	recipient, err := s.Store.Recipient(id.Username)
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	if r.Method == "PUT" {
		var p notify.Preferences
		if !decode(w, r, &p) {
			return
		}
		p.ChatID = ""
		if err = p.Validate(); err != nil {
			fail(w, 400, err.Error())
			return
		}
		recipient = store.Recipient{Username: id.Username, UID: id.UID, Principal: id.Principal, Preferences: p}
		if err = s.Store.SaveRecipient(recipient); err != nil {
			fail(w, 503, "delivery.unavailable")
			return
		}
	}
	c, err := s.Store.DeliveryConfig()
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	devices, err := s.Store.PushDevices(id.Username)
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	history, err := s.Store.Deliveries(id.Username, false)
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	jsonResponse(w, 200, map[string]any{"preferences": recipient.Preferences, "publicKey": c.PublicKey, "devices": devices, "history": history, "available": map[string]bool{"email": c.SMTP.Enabled, "telegram": c.TelegramEnabled, "push": c.PublicKey != "" && c.Contact != ""}})
}
func (s *Server) deliveryPush(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	if r.Method == "DELETE" {
		var input struct {
			ID string `json:"id"`
		}
		if !decode(w, r, &input) {
			return
		}
		if len(input.ID) != 64 {
			fail(w, 400, "delivery.invalidSubscription")
			return
		}
		if s.Store.RemovePush(id.Username, input.ID) != nil {
			fail(w, 503, "delivery.unavailable")
			return
		}
		w.WriteHeader(204)
		return
	}
	var sub notify.Subscription
	if !decode(w, r, &sub) {
		return
	}
	if err := sub.Validate(); err != nil {
		fail(w, 400, err.Error())
		return
	}
	devices, err := s.Store.PushDevices(id.Username)
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	existing := false
	for _, device := range devices {
		var current notify.Subscription
		if s.Store.NotificationSecret("push:"+id.Username+":"+device, &current) == nil && current.Endpoint == sub.Endpoint {
			existing = true
			break
		}
	}
	if len(devices) >= 10 && !existing {
		fail(w, 409, "delivery.deviceLimit")
		return
	}
	key, err := s.Store.SavePush(id.Username, sub)
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	jsonResponse(w, 200, map[string]string{"id": key})
}
func (s *Server) deliveryTest(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	if !s.permit("notification-test:" + id.Username) {
		fail(w, 429, "delivery.rateLimited")
		return
	}
	var input struct {
		Channel string `json:"channel"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Channel != "email" && input.Channel != "telegram" && input.Channel != "push" {
		fail(w, 400, "delivery.invalidRoutes")
		return
	}
	recipient, err := s.Store.Recipient(id.Username)
	if err != nil || !recipient.Preferences.Enabled {
		fail(w, 409, "delivery.enableFirst")
		return
	}
	devices := []string{""}
	if input.Channel == "push" {
		devices, err = s.Store.PushDevices(id.Username)
		if err != nil || len(devices) == 0 {
			fail(w, 409, "delivery.notConfigured")
			return
		}
	}
	for _, d := range devices {
		if s.Store.QueueTest(id.Username, input.Channel, d) != nil {
			fail(w, 503, "delivery.unavailable")
			return
		}
	}
	jsonResponse(w, 202, map[string]string{"status": "queued"})
}
func eventForAlert(a store.Alert) notify.Event {
	e := notify.Event{ID: a.ID, Revision: a.Updated, Severity: a.Severity, Kind: "generic", Route: "/?panel=notifications"}
	if e.Severity == "success" {
		e.Severity = "info"
	}
	switch {
	case a.ID == "cpu-hot" || a.ID == "system-full":
		e.Kind = a.ID
		e.Severity = "critical"
		e.Resolved = !a.Active
	case a.ID == "cooling-stale":
		e.Kind = a.ID
		e.Resolved = !a.Active
	case strings.HasPrefix(a.ID, "smart:"):
		e.Kind = "smart"
		e.Object = strings.TrimPrefix(a.ID, "smart:")
		e.Route = "/storage/disks"
		e.Resolved = !a.Active
		if strings.HasPrefix(a.Message, "SMART: disk failure:") {
			e.Severity = "critical"
		}
	case strings.HasPrefix(a.ID, "heat:"):
		e.Kind = "heat"
		e.Object = strings.TrimPrefix(a.ID, "heat:")
		e.Route = "/storage/disks"
		e.Resolved = !a.Active
	case strings.HasPrefix(a.ID, "job:"):
		e.Kind = "job"
		e.Route = "/?panel=jobs"
		e.Resolved = !a.Active
	case strings.HasPrefix(a.ID, "update:"):
		e.Kind = "update"
		e.Route = "/settings/updates"
	case strings.HasPrefix(a.ID, "device:"):
		e.Route = "/storage/disks"
		switch {
		case strings.Contains(a.Message, "check storage."):
			e.Kind = "device-busy"
		case strings.HasPrefix(a.Message, "Drive connected:"):
			e.Kind = "device-connected"
		case strings.HasPrefix(a.Message, "Drive disconnected:"):
			e.Kind = "device-disconnected"
		default:
			e.Kind = "device-ejected"
		}
	}
	return e
}
func (s *Server) runDelivery(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.deliveryCycle(ctx); err != nil {
				log.Print("Notification delivery cycle unavailable")
			}
		}
	}
}
func (s *Server) deliveryCycle(ctx context.Context) error {
	s.Store.PruneDeliveries()
	visible := map[string]map[string]notify.Event{}
	recipients, err := s.Store.Recipients()
	if err != nil {
		return err
	}
	for _, recipient := range recipients {
		id, err := s.lookupIdentity(recipient.Username, s.Allowed)
		if err != nil || id.UID != recipient.UID || id.Principal != recipient.Principal {
			continue
		}
		alerts, err := s.recipientAlerts(ctx, id)
		if err != nil {
			continue
		}
		visible[recipient.Username] = map[string]notify.Event{}
		for _, a := range alerts {
			visible[recipient.Username][a.ID] = eventForAlert(a)
			stamp, err := time.Parse(time.RFC3339, a.Updated)
			if err == nil {
				if err = s.Store.ObserveNotification(recipient, eventForAlert(a), stamp); err != nil {
					return err
				}
			}
		}
	}
	pending, err := s.Store.Deliveries("", true)
	if err != nil {
		return err
	}
	c, err := s.Store.DeliveryConfig()
	if err != nil {
		return err
	}
	for _, d := range pending {
		r, err := s.Store.Recipient(d.User)
		if err != nil {
			return err
		}
		id, err := s.lookupIdentity(d.User, s.Allowed)
		if err != nil || id.UID != r.UID || id.Principal != r.Principal || !r.Preferences.Enabled || (id.Role != "admin" && d.Event.Kind != "test" && d.Event.Kind != "job") {
			if err := s.Store.FinishDelivery(d, "cancelled", "delivery.accessChanged"); err != nil {
				return err
			}
			continue
		}
		if d.Event.Kind != "test" {
			current, ok := visible[d.User][d.Event.ID]
			if !ok || current.Resolved != d.Event.Resolved || current.Severity != d.Event.Severity {
				if _, known := visible[d.User]; !known {
					continue
				}
				if err := s.Store.FinishDelivery(d, "cancelled", "delivery.eventChanged"); err != nil {
					return err
				}
				continue
			}
		}
		p, err := s.Store.Preferences(d.User)
		if err != nil {
			return err
		}
		m := d.Event.Message(p.Language)
		sendCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		switch d.Channel {
		case "email":
			err = notify.SendEmail(sendCtx, c.SMTP, r.Preferences.Email, m)
		case "telegram":
			link, linkErr := s.Store.TelegramLink(id.Username, id.UID, id.Principal, telegramBotKey(c.TelegramToken))
			if linkErr != nil {
				cancel()
				return linkErr
			}
			r.Preferences.ChatID = link.ChatID
			err = notify.SendTelegram(sendCtx, c, r.Preferences.ChatID, m)
		case "push":
			var sub notify.Subscription
			if d.Device == "" {
				err = errors.New("delivery.notConfigured")
			} else if err = s.Store.NotificationSecret("push:"+d.User+":"+d.Device, &sub); err == nil {
				err = notify.SendPush(sendCtx, c, sub, m)
				if errors.Is(err, notify.ErrExpired) {
					s.Store.RemovePush(d.User, d.Device)
				}
			}
		default:
			err = errors.New("delivery.invalidRoutes")
		}
		cancel()
		status, reason := "sent", ""
		if err != nil {
			status = "pending"
			reason = err.Error()
			if !strings.HasPrefix(reason, "delivery.") {
				reason = "delivery.unavailable"
			}
			if d.Attempts >= 4 || errors.Is(err, notify.ErrExpired) || reason == "delivery.notConfigured" {
				status = "failed"
			}
		}
		if err = s.Store.FinishDelivery(d, status, reason); err != nil {
			return err
		}
	}
	s.Store.PruneDeliveries()
	return nil
}

func (s *Server) recipientAlerts(ctx context.Context, id auth.Identity) ([]store.Alert, error) {
	alerts, err := s.notifications(ctx, id.Username)
	if err != nil {
		return nil, err
	}
	if id.Role == "admin" {
		return alerts, nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://agent/job-feed", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.Agent.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("job feed unavailable")
	}
	var jobs []management.Job
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jobs); err != nil {
		return nil, err
	}
	own := map[string]bool{}
	for _, j := range jobs {
		if j.User == id.Username {
			own["job:"+j.ID] = true
		}
	}
	result := []store.Alert{}
	for _, a := range alerts {
		if own[a.ID] {
			result = append(result, a)
		}
	}
	return result, nil
}

func (s *Server) deliveryRetry(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	if !s.permit("notification-test:" + id.Username) {
		fail(w, 429, "delivery.rateLimited")
		return
	}
	var input struct {
		ID int64 `json:"id"`
	}
	if !decode(w, r, &input) {
		return
	}
	if err := s.Store.RetryDelivery(id.Username, input.ID); err != nil {
		fail(w, 409, "delivery.notRetryable")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) smtpTest(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	if id.Role != "admin" {
		fail(w, 403, "Administrator permissions required")
		return
	}
	if !s.permit("notification-test:" + id.Username) {
		fail(w, 429, "delivery.rateLimited")
		return
	}
	var input struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.Email = strings.TrimSpace(input.Email)
	if a, err := mail.ParseAddress(input.Email); err != nil || a.Address != input.Email || strings.ContainsAny(input.Email, "\r\n") {
		fail(w, 400, "delivery.invalidEmail")
		return
	}
	c, err := s.Store.DeliveryConfig()
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	if !c.SMTP.Enabled {
		fail(w, 409, "delivery.notConfigured")
		return
	}
	p, err := s.Store.Preferences(id.Username)
	if err != nil {
		fail(w, 503, "delivery.unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	err = notify.SendEmail(ctx, c.SMTP, input.Email, (notify.Event{Kind: "test", Severity: "info"}).Message(p.Language))
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	s.Store.Audit(id.Username, id.Username, "notifications.smtp-test", "succeeded")
	w.WriteHeader(http.StatusNoContent)
}
