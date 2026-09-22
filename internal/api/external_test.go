package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/external"
	"panasms.local/backend/internal/store"
	"strings"
	"testing"
	"time"
)

type externalTransport func(*http.Request) (*http.Response, error)

func (f externalTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func externalJSON(status int, body any) *http.Response {
	raw, _ := json.Marshal(body)
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(raw))), Header: http.Header{"Content-Type": []string{"application/json"}}}
}
func externalRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, "http://nas/api/v1/external/"+path, strings.NewReader(body))
	r.Header.Set("Origin", "http://nas")
	r.Header.Set("X-PaNasMs-Request", "1")
	return r
}
func externalFixture(t *testing.T) (*Server, *http.Cookie, *externalFlow) {
	s := testServer(t)
	c := store.ExternalConfig{ClientID: "test.apps.googleusercontent.com", ClientSecret: "fake-secret", Enabled: true, Revision: "revision"}
	if err := s.Store.SaveExternalConfig("google", c); err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Username: "alice", UID: 1000, Principal: "principal", Epoch: "epoch", Role: "user"}
	if err := s.Store.BindAccount(id.Username, id.UID, id.Principal); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.LinkExternal(store.ExternalConnection{ID: "connection", Provider: "google", Subject: "google-id", Username: id.Username, UID: id.UID, Principal: id.Principal, Email: "old@example.test"}); err != nil {
		t.Fatal(err)
	}
	s.Agent = &http.Client{Transport: externalTransport(func(r *http.Request) (*http.Response, error) { return externalJSON(200, id), nil })}
	s.external.client = &http.Client{Transport: externalTransport(func(r *http.Request) (*http.Response, error) {
		return externalJSON(200, map[string]string{"code": "one-time-code"}), nil
	})}
	s.external.exchange = func(_ context.Context, _ *http.Client, clientID, secret, code, nonce, verifier string) (external.Account, error) {
		return external.Account{Subject: "google-id", Email: "new@example.test", Name: "Alice"}, nil
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, externalRequest("POST", "google/start", `{"purpose":"login"}`))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	flow := s.external.pending[externalDigest(cookie.Value)]
	return s, cookie, flow
}
func pollExternal(s *Server, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := externalRequest("POST", "google/poll", `{}`)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func TestExternalLoginBindingAndReplay(t *testing.T) {
	s, cookie, _ := externalFixture(t)
	w := pollExternal(s, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "authenticated") {
		t.Fatal(w.Code, w.Body.String())
	}
	var token string
	for _, c := range w.Result().Cookies() {
		if c.Name == "panasms_session" {
			token = c.Value
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Fatal("unsafe cookie")
			}
		}
	}
	user, err := s.Store.User(token)
	if err != nil || user != "alice" {
		t.Fatal(user, err)
	}
	if !s.Store.SessionMatches(token, 1000, "epoch") {
		t.Fatal("unbound session")
	}
	if pollExternal(s, cookie).Code != 410 {
		t.Fatal("flow replay")
	}
}
func TestExternalLoginFailsClosed(t *testing.T) {
	for _, variant := range []string{"cookie", "expired", "revision", "disabled", "wrong-subject", "identity-failure", "uid", "principal", "blocked"} {
		t.Run(variant, func(t *testing.T) {
			s, cookie, flow := externalFixture(t)
			switch variant {
			case "cookie":
				cookie.Value = "another-browser"
			case "expired":
				flow.Expires = time.Now().Add(-time.Minute)
			case "revision", "disabled":
				c, _ := s.Store.ExternalConfig("google")
				if variant == "revision" {
					c.Revision = "new"
				} else {
					c.Enabled = false
				}
				s.Store.SaveExternalConfig("google", c)
			case "wrong-subject", "identity-failure":
				s.external.exchange = func(context.Context, *http.Client, string, string, string, string, string) (external.Account, error) {
					if variant == "identity-failure" {
						return external.Account{}, errors.New("bad JWT")
					}
					return external.Account{Subject: "someone-else", Email: "old@example.test"}, nil
				}
			default:
				s.Agent = &http.Client{Transport: externalTransport(func(*http.Request) (*http.Response, error) {
					id := auth.Identity{Username: "alice", UID: 1000, Principal: "principal"}
					code := 200
					if variant == "uid" {
						id.UID = 1001
					}
					if variant == "principal" {
						id.Principal = "recreated"
					}
					if variant == "blocked" {
						code = 403
					}
					return externalJSON(code, id), nil
				})}
			}
			w := pollExternal(s, cookie)
			if w.Code < 400 {
				t.Fatal("accepted", variant, w.Code)
			}
			for _, c := range w.Result().Cookies() {
				if c.Name == "panasms_session" && c.Value != "" {
					t.Fatal("session issued")
				}
			}
		})
	}
}
func TestExternalCancelDuringExchange(t *testing.T) {
	s, cookie, _ := externalFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	s.external.exchange = func(context.Context, *http.Client, string, string, string, string, string) (external.Account, error) {
		close(entered)
		<-release
		return external.Account{Subject: "google-id"}, nil
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- pollExternal(s, cookie) }()
	<-entered
	r := externalRequest("POST", "google/cancel", `{}`)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	close(release)
	if w.Code != 204 || (<-result).Code != 410 {
		t.Fatal("cancel ignored")
	}
}
func TestExternalPendingAndRetry(t *testing.T) {
	s, cookie, flow := externalFixture(t)
	s.external.client = &http.Client{Transport: externalTransport(func(*http.Request) (*http.Response, error) {
		return externalJSON(404, map[string]string{"status": "pending"}), nil
	})}
	if pollExternal(s, cookie).Code != 202 {
		t.Fatal("not pending")
	}
	flow.NextPoll = time.Time{}
	s.external.client = &http.Client{Transport: externalTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })}
	if pollExternal(s, cookie).Code != 503 || s.external.pending[externalDigest(cookie.Value)] != flow {
		t.Fatal("lost retry")
	}
}
func TestExternalSettingsAndOwnerAccess(t *testing.T) {
	s, _, _ := externalFixture(t)
	for _, role := range []string{"user", "admin"} {
		r := externalRequest("GET", "settings/google", "")
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, auth.Identity{Role: role}))
		w := httptest.NewRecorder()
		s.externalSettings(w, r)
		if role == "user" && w.Code != 403 || role == "admin" && (w.Code != 200 || strings.Contains(w.Body.String(), "fake-secret")) {
			t.Fatal(role, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"settings/google", "connections"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, externalRequest("GET", path, ""))
		if w.Code != 401 {
			t.Fatal(path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, externalRequest("POST", "google/start", `{"purpose":"link","password":"fake"}`))
	if w.Code != 401 {
		t.Fatal("anonymous linking")
	}
	user := auth.Identity{Username: "bob", UID: 1001, Principal: "other", Role: "user"}
	r := externalRequest("GET", "connections", "")
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, user))
	w = httptest.NewRecorder()
	s.externalConnections(w, r)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatal("other user's connections exposed")
	}
}

func TestExternalSettingsPreserveSecretAndInvalidateFlows(t *testing.T) {
	s, cookie, _ := externalFixture(t)
	r := externalRequest("PUT", "settings/google", `{"clientId":"test.apps.googleusercontent.com","clientSecret":"","enabled":false}`)
	r = r.WithContext(context.WithValue(r.Context(), identityKey{}, auth.Identity{Username: "admin", Role: "admin"}))
	w := httptest.NewRecorder()
	s.externalSettings(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "fake-secret") {
		t.Fatal(w.Code, w.Body.String())
	}
	c, err := s.Store.ExternalConfig("google")
	if err != nil || c.ClientSecret != "fake-secret" || c.Enabled || c.Revision == "revision" {
		t.Fatal("configuration update", err)
	}
	if pollExternal(s, cookie).Code != 410 {
		t.Fatal("settings change kept flow")
	}
	w = httptest.NewRecorder()
	s.externalProviders(w, externalRequest("GET", "providers", ""))
	if strings.TrimSpace(w.Body.String()) != `{"google":{"enabled":false}}` {
		t.Fatal(w.Body.String())
	}
}
func TestExternalPasswordProofChecksIdentity(t *testing.T) {
	s, _, _ := externalFixture(t)
	id := auth.Identity{Username: "alice", UID: 1000, Principal: "principal", Epoch: "epoch"}
	r := externalRequest("POST", "google/start", "")
	if s.externalReauthenticate(r, id, "") {
		t.Fatal("empty proof accepted")
	}
	if !s.externalReauthenticate(r, id, "test-password") {
		t.Fatal("valid proof failed")
	}
	id.UID = 1001
	if s.externalReauthenticate(r, id, "test-password") {
		t.Fatal("wrong identity accepted")
	}
}
