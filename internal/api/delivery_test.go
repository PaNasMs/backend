package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/management"
	"panasms.local/backend/internal/store"
	"strings"
	"testing"
)

func TestNotificationConfigAdministratorAndSecretRedaction(t *testing.T) {
	s := testServer(t)
	for _, role := range []string{"user", "admin"} {
		r := httptest.NewRequest("PUT", "/", strings.NewReader(`{"smtp":{"host":"smtp.test","port":587,"security":"starttls","username":"nas","password":"secret-pass","from":"nas@example.org","enabled":true},"telegramEnabled":false,"contact":"nas@example.org"}`))
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, auth.Identity{Username: "alice", Role: role}))
		w := httptest.NewRecorder()
		s.deliverySettings(w, r)
		if role == "user" {
			if w.Code != 403 {
				t.Fatal(w.Code)
			}
			continue
		}
		if w.Code != 200 || strings.Contains(w.Body.String(), "secret-pass") || strings.Contains(w.Body.String(), "privateKey") {
			t.Fatal(w.Code, w.Body.String())
		}
		var result map[string]any
		json.Unmarshal(w.Body.Bytes(), &result)
		if result["passwordConfigured"] != true {
			t.Fatal(result)
		}
	}
}
func TestNotificationClassification(t *testing.T) {
	for _, tc := range []struct{ id, message, severity string }{{"cpu-hot", "", "critical"}, {"system-full", "", "critical"}, {"smart:/dev/sda", "SMART: disk failure:", "critical"}, {"heat:/dev/sda", "", "warning"}, {"job:a", "", "error"}} {
		a := store.Alert{ID: tc.id, Message: tc.message, Active: true, Severity: tc.severity}
		e := eventForAlert(a, nil)
		if e.Severity != tc.severity || e.Resolved {
			t.Fatal(e)
		}
	}
}
func TestNotificationSettingsNotAvailableToOrdinaryUser(t *testing.T) {
	id := auth.Identity{Role: "user"}
	for _, p := range []string{"notification-profile", "notification-push", "notification-test"} {
		if !userRoute(id, httptest.NewRequest("POST", "/api/v1/"+p, nil)) {
			t.Fatal(p)
		}
	}
	if userRoute(id, httptest.NewRequest("PUT", "/api/v1/notification-settings", nil)) {
		t.Fatal("admin settings exposed")
	}
}

func TestOrdinaryRecipientOnlySeesOwnJobs(t *testing.T) {
	s := testServer(t)
	s.Store.Alert("cpu-hot", "CPU temperature ≥ 80 °C", true)
	s.Store.Alert("job:mine", "Operation file.copy: failed", true)
	s.Store.Alert("job:other", "Operation user.password: failed", true)
	s.Agent = &http.Client{Transport: accountTestTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[{"id":"mine","user":"alice","needsReview":true},{"id":"other","user":"bob","needsReview":true}]`))}, nil
	})}
	alerts, err := s.recipientAlerts(context.Background(), auth.Identity{Username: "alice", Role: "user"})
	if err != nil || len(alerts) != 1 || alerts[0].ID != "job:mine" {
		t.Fatal(alerts, err)
	}
}

func TestSMTPTestAuthorizationAndValidation(t *testing.T) {
	for _, tc := range []struct {
		role, body string
		status     int
	}{
		{"user", `{"email":"alice@example.org"}`, 403},
		{"admin", `{"email":"bad"}`, 400},
		{"admin", `{"email":"alice@example.org\r\nBcc: other@example.org"}`, 400},
		{"admin", `{"email":"alice@example.org"}`, 409},
	} {
		s := testServer(t)
		r := httptest.NewRequest("POST", "/api/v1/notification-smtp-test", strings.NewReader(tc.body))
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, auth.Identity{Username: "alice", Role: tc.role}))
		w := httptest.NewRecorder()
		s.smtpTest(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s: got %d: %s", tc.role, w.Code, w.Body.String())
		}
	}
	if userRoute(auth.Identity{Role: "user"}, httptest.NewRequest("POST", "/api/v1/notification-smtp-test", nil)) {
		t.Fatal("SMTP test exposed to ordinary user")
	}
}

func TestTelegramTestUsesLinkedProfileOnly(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("POST", "/api/v1/notification-telegram-test", strings.NewReader(`{"chatId":"12345"}`))
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, auth.Identity{Username: "alice", Role: "user"}))
	w := httptest.NewRecorder()
	s.telegramTest(w, r)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	if !userRoute(auth.Identity{Role: "user"}, r) {
		t.Fatal("Own Telegram test not allowed")
	}
}

func TestJobNotificationCarriesTaskDetails(t *testing.T) {
	a := store.Alert{ID: "job:j1", Message: "Operation file.copy: No space left on device", Active: true, Severity: "error"}
	e := eventForAlert(a, map[string]management.Job{"j1": {ID: "j1", Action: "file.move", Status: "interrupted", Target: "/srv/a", Stage: "Interrupted"}})
	if e.Action != "file.move" || e.Status != "interrupted" || e.Object != "/srv/a" || e.Detail != "Interrupted" {
		t.Fatal(e)
	}
	e = eventForAlert(a, nil)
	if e.Action != "file.copy" || e.Status != "failed" || e.Detail != "No space left on device" || e.Object != "" {
		t.Fatal("fallback to alert text", e)
	}
	a.Severity, a.Message = "warning", "Operation share.save: Cancelled at a safe point"
	if e = eventForAlert(a, nil); e.Status != "cancelled" {
		t.Fatal(e)
	}
}

func TestAlertedJobsRequestsOnlyActiveJobAlerts(t *testing.T) {
	s := testServer(t)
	s.Store.Alert("job:j1", "Operation file.copy: failed", true)
	s.Store.Alert("job:old", "Operation file.copy: failed", false)
	s.Store.Alert("cpu-hot", "CPU", true)
	var query string
	s.Agent = &http.Client{Transport: accountTestTransport(func(r *http.Request) (*http.Response, error) {
		query = r.URL.RawQuery
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[{"id":"j1","action":"file.copy","target":"/srv/a","status":"failed","stage":"boom"}]`))}, nil
	})}
	jobs := s.alertedJobs(context.Background())
	if query != "alert=j1" || jobs["j1"].Target != "/srv/a" || len(jobs) != 1 {
		t.Fatal(query, jobs)
	}
}
