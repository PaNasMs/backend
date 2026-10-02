package api

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"os"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/external"
	"panasms.local/backend/internal/modules"
	"panasms.local/backend/internal/store"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func grantFixture(t *testing.T) (*Server, *http.Cookie) {
	s, _, _ := externalFixture(t)
	s.lookupIdentity = func(string, map[string]bool) (auth.Identity, error) {
		return auth.Identity{Username: "alice", UID: 1000, Principal: "principal", Epoch: "epoch", Role: "user"}, nil
	}
	old := modules.Root
	modules.Root = t.TempDir()
	t.Cleanup(func() { modules.Root = old })
	writeModule(t, true, "installation")
	token, err := s.Store.Session("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Store.SessionDetails(token, 1000, "epoch", "", "test"); err != nil {
		t.Fatal(err)
	}
	s.external.exchangeGrant = func(context.Context, *http.Client, string, string, string, string, string, string) (external.Authorization, error) {
		return external.Authorization{Account: external.Account{Subject: "google-id"}, Token: &oauth2.Token{AccessToken: "secret-access", RefreshToken: "secret-refresh", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}, nil
	}
	return s, &http.Cookie{Name: "panasms_session", Value: token}
}
func writeModule(t *testing.T, enabled bool, installation string) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"cloud-sync": map[string]any{"id": "cloud-sync", "enabled": enabled, "installation": installation}})
	if err := os.WriteFile(filepath.Join(modules.Root, "registry.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func startGrant(t *testing.T, s *Server, session *http.Cookie) *http.Cookie {
	t.Helper()
	r := externalRequest("POST", "google/start", `{"purpose":"grant","password":"test","connectionId":"connection","consumer":"cloud-sync","capability":"google-drive"}`)
	r.AddCookie(session)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	return w.Result().Cookies()[0]
}
func finishGrant(s *Server, session, flow *http.Cookie) *httptest.ResponseRecorder {
	r := externalRequest("POST", "google/poll", `{}`)
	r.AddCookie(session)
	r.AddCookie(flow)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func tokenGrant(s *Server, id, consumer, owner string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "http://core/v1/token", strings.NewReader(`{"grantId":"`+id+`","owner":"`+owner+`"}`))
	s.serveGrantToken(w, r, consumer)
	return w
}
func TestGrantConsentAndModuleToken(t *testing.T) {
	s, session := grantFixture(t)
	flow := startGrant(t, s, session)
	w := finishGrant(s, session, flow)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["status"] != "granted" || strings.Contains(w.Body.String(), "secret") {
		t.Fatal("browser exposed tokens")
	}
	id := result["grantId"]
	if tokenGrant(s, id, "files", "alice").Code != 403 || tokenGrant(s, id, "cloud-sync", "bob").Code != 403 {
		t.Fatal("consumer/owner isolation")
	}
	w = tokenGrant(s, id, "cloud-sync", "alice")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "secret-access") || strings.Contains(w.Body.String(), "secret-refresh") {
		t.Fatal(w.Code, w.Body.String())
	}
	writeModule(t, false, "installation")
	if tokenGrant(s, id, "cloud-sync", "alice").Code != 403 {
		t.Fatal("disabled module")
	}
	writeModule(t, true, "new-installation")
	if tokenGrant(s, id, "cloud-sync", "alice").Code != 409 {
		t.Fatal("reinstalled module inherited grant")
	}
}
func TestGrantRejectsChangedConsentContext(t *testing.T) {
	for _, variant := range []string{"subject", "disabled", "reinstall", "unlink", "cancel"} {
		t.Run(variant, func(t *testing.T) {
			s, session := grantFixture(t)
			flow := startGrant(t, s, session)
			switch variant {
			case "subject":
				s.external.exchangeGrant = func(context.Context, *http.Client, string, string, string, string, string, string) (external.Authorization, error) {
					return external.Authorization{Account: external.Account{Subject: "wrong"}}, nil
				}
			case "disabled":
				writeModule(t, false, "installation")
			case "reinstall":
				writeModule(t, true, "other")
			case "unlink":
				s.Store.UnlinkExternal("alice", "connection")
			case "cancel":
				delete(s.external.pending, externalDigest(flow.Value))
			}
			if w := finishGrant(s, session, flow); w.Code == 200 {
				t.Fatal("unsafe grant accepted")
			}
			grants, _ := s.Store.ExternalGrants("alice", 1000, "principal")
			if len(grants) != 0 {
				t.Fatal("grant persisted")
			}
		})
	}
}
func TestBrokerCannotBeReachedFromPublicHTTP(t *testing.T) {
	s, _ := grantFixture(t)
	r := httptest.NewRequest("POST", "http://nas/v1/token", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	s.grantBroker(w, r)
	if w.Code != 403 {
		t.Fatal("missing kernel peer accepted")
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "accessToken") {
		t.Fatal("public broker exposed")
	}
	for input, want := range map[string]string{"0::/system.slice/panasms-module-cloud-sync.service": "cloud-sync", "0::/user.slice/panasms-module-cloud-sync.service": "", "0::/system.slice/panasms-module-files.service": "files", "0::/system.slice/panasms-module-terminal.service": "", "0::/system.slice/panasms-module-cloud-sync.service-evil": ""} {
		if peerConsumer(input) != want {
			t.Fatal(input)
		}
	}
}
func TestGrantRefreshPersistsAndRevocationFailsClosed(t *testing.T) {
	s, session := grantFixture(t)
	flow := startGrant(t, s, session)
	w := finishGrant(s, session, flow)
	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	id := result["grantId"]
	g, err := s.Store.ExternalGrant(id)
	if err != nil {
		t.Fatal(err)
	}
	g.Token.Expiry = time.Now().Add(-time.Hour)
	s.Store.SaveAccountAuthorization(g)
	calls := 0
	s.external.client = &http.Client{Transport: externalTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "secret-refresh" {
			t.Fatal("wrong refresh request")
		}
		return externalJSON(200, map[string]any{"access_token": "renewed", "refresh_token": "rotated", "token_type": "Bearer", "expires_in": 3600}), nil
	})}
	w = tokenGrant(s, id, "cloud-sync", "alice")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	g, _ = s.Store.AccountAuthorization(g.ConnectionID, g.Scope)
	if calls != 1 || g.Token.RefreshToken != "rotated" {
		t.Fatal("rotation lost")
	}
	tokenGrant(s, id, "cloud-sync", "alice")
	if calls != 1 {
		t.Fatal("valid token unnecessarily refreshed")
	}
	g.Token.Expiry = time.Now().Add(-time.Hour)
	s.Store.SaveAccountAuthorization(g)
	s.external.client = &http.Client{Transport: externalTransport(func(*http.Request) (*http.Response, error) {
		return externalJSON(400, map[string]string{"error": "invalid_grant"}), nil
	})}
	if tokenGrant(s, id, "cloud-sync", "alice").Code != 409 {
		t.Fatal("revoked token not reported")
	}
	g, _ = s.Store.ExternalGrant(id)
	if tokenGrant(s, id, "cloud-sync", "alice").Code != 409 {
		t.Fatal("reconnect state lost on retry")
	}
	if g.Status != "reconnect_required" || g.Token != nil {
		t.Fatal("revoked credentials retained")
	}
}

func TestGrantCancellationDuringExchange(t *testing.T) {
	s, session := grantFixture(t)
	flow := startGrant(t, s, session)
	entered := make(chan struct{})
	release := make(chan struct{})
	exchange := s.external.exchangeGrant
	s.external.exchangeGrant = func(ctx context.Context, c *http.Client, a, b, d, e, f, g string) (external.Authorization, error) {
		close(entered)
		<-release
		return exchange(ctx, c, a, b, d, e, f, g)
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- finishGrant(s, session, flow) }()
	<-entered
	r := externalRequest("POST", "google/cancel", `{}`)
	r.AddCookie(flow)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	close(release)
	if (<-result).Code != 410 {
		t.Fatal("cancelled grant persisted")
	}
	grants, _ := s.Store.ExternalGrants("alice", 1000, "principal")
	if len(grants) != 0 {
		t.Fatal("cancelled tokens stored")
	}
}
func TestGrantTransientRefreshAndAccountEpoch(t *testing.T) {
	s, session := grantFixture(t)
	flow := startGrant(t, s, session)
	w := finishGrant(s, session, flow)
	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	id := result["grantId"]
	g, _ := s.Store.ExternalGrant(id)
	g.Token.Expiry = time.Now().Add(-time.Hour)
	s.Store.SaveAccountAuthorization(g)
	s.external.client = &http.Client{Transport: externalTransport(func(*http.Request) (*http.Response, error) {
		return externalJSON(503, map[string]string{"error": "temporarily_unavailable"}), nil
	})}
	if tokenGrant(s, id, "cloud-sync", "alice").Code != 503 {
		t.Fatal("temporary failure")
	}
	g, _ = s.Store.ExternalGrant(id)
	if g.Status != "active" || g.Token.RefreshToken == "" {
		t.Fatal("temporary failure erased consent")
	}
	s.Agent = &http.Client{Transport: externalTransport(func(*http.Request) (*http.Response, error) {
		return externalJSON(200, auth.Identity{Username: "alice", UID: 1000, Principal: "principal", Epoch: "new"}), nil
	})}
	if tokenGrant(s, id, "cloud-sync", "alice").Code != 409 {
		t.Fatal("changed epoch reused grant")
	}
}

func TestDropboxGrantBindingAndBroker(t *testing.T) {
	for _, wrongIdentity := range []bool{false, true} {
		t.Run(fmt.Sprint(wrongIdentity), func(t *testing.T) {
			s, session := grantFixture(t)
			if err := s.Store.SaveExternalConfig("dropbox", store.ExternalConfig{ClientID: "dropbox-id", ClientSecret: "secret", Enabled: true, Revision: "dropbox-revision"}); err != nil {
				t.Fatal(err)
			}
			if err := s.Store.LinkExternal(store.ExternalConnection{ID: "dropbox-connection", Provider: "dropbox", Subject: "dbid:alice", Username: "alice", UID: 1000, Principal: "principal", Email: "alice@example.test"}); err != nil {
				t.Fatal(err)
			}
			s.external.client = &http.Client{Transport: externalTransport(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Host {
				case "panasms-oauth-gateway.panasms.workers.dev":
					return externalJSON(200, map[string]string{"code": "one-time-code"}), nil
				case "api.dropboxapi.com":
					if r.URL.Path == "/oauth2/token" {
						return externalJSON(200, map[string]any{"access_token": "private-access", "token_type": "bearer", "refresh_token": "private-refresh", "expires_in": 14400, "scope": external.DropboxFilesScope}), nil
					}
					subject := "dbid:alice"
					if wrongIdentity {
						subject = "dbid:bob"
					}
					return externalJSON(200, map[string]any{"account_id": subject, "email": "alice@example.test", "email_verified": true}), nil
				default:
					t.Fatal("unexpected endpoint", r.URL)
					return nil, nil
				}
			})}
			r := externalRequest("POST", "dropbox/start", `{"purpose":"grant","password":"test","connectionId":"dropbox-connection","consumer":"cloud-sync","capability":"dropbox-files"}`)
			r.AddCookie(session)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			flow := w.Result().Cookies()[0]
			r = externalRequest("POST", "dropbox/poll", `{}`)
			r.AddCookie(session)
			r.AddCookie(flow)
			w = httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if wrongIdentity {
				if w.Code != 403 {
					t.Fatal("wrong account accepted", w.Code)
				}
				return
			}
			if w.Code != 200 || strings.Contains(w.Body.String(), "private") {
				t.Fatal(w.Code, w.Body.String())
			}
			var result map[string]string
			json.Unmarshal(w.Body.Bytes(), &result)
			if tokenGrant(s, result["grantId"], "cloud-sync", "alice").Code != 200 {
				t.Fatal("Dropbox broker denied valid grant")
			}
			if tokenGrant(s, result["grantId"], "cloud-sync", "bob").Code != 403 {
				t.Fatal("owner isolation failed")
			}
			// Changing Google's configuration must not invalidate Dropbox permissions.
			s.Store.SaveExternalConfig("google", store.ExternalConfig{Enabled: false, Revision: "changed"})
			r = externalRequest("GET", "grants", "")
			r = r.WithContext(context.WithValue(r.Context(), identityKey{}, auth.Identity{Username: "alice", UID: 1000, Principal: "principal", Epoch: "epoch"}))
			w = httptest.NewRecorder()
			s.externalGrants(w, r)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"active"`) {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestSlowRefreshDoesNotBlockOAuthAndCannotUndoRevocation(t *testing.T) {
	s, session := grantFixture(t)
	flow := startGrant(t, s, session)
	w := finishGrant(s, session, flow)
	var result map[string]string
	json.Unmarshal(w.Body.Bytes(), &result)
	g, err := s.Store.ExternalGrant(result["grantId"])
	if err != nil {
		t.Fatal(err)
	}
	g.Token.Expiry = time.Now().Add(-time.Hour)
	s.Store.SaveAccountAuthorization(g)
	s.external.client = &http.Client{Transport: externalTransport(func(*http.Request) (*http.Response, error) {
		if !s.external.TryLock() {
			t.Fatal("network refresh holds OAuth mutex")
		}
		defer s.external.Unlock()
		if err := s.Store.SetGrantStatus(g.ID, "reconnect_required"); err != nil {
			t.Fatal(err)
		}
		return externalJSON(200, map[string]any{"access_token": "fresh", "token_type": "Bearer", "expires_in": 3600}), nil
	})}
	if response := tokenGrant(s, g.ID, "cloud-sync", "alice"); response.Code != 403 {
		t.Fatal(response.Code, response.Body.String())
	}
}
