package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"panasms.local/backend/internal/modules"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccountConsentReusedForLaterInstalledModule(t *testing.T) {
	s, session := grantFixture(t)
	result := finishGrant(s, session, startGrant(t, s, session))
	if result.Code != 200 {
		t.Fatal(result.Body.String())
	}
	raw := `{"cloud-sync":{"id":"cloud-sync","enabled":true,"installation":"installation"},"files":{"id":"files","enabled":true,"installation":"new-files"}}`
	if err := os.WriteFile(filepath.Join(modules.Root, "registry.json"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	request := func(capability string) *httptest.ResponseRecorder {
		r := externalRequest("POST", "google/start", `{"purpose":"grant","connectionId":"connection","consumer":"files","capability":"`+capability+`"}`)
		r.AddCookie(session)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w := request("google-drive")
	var reply map[string]string
	json.Unmarshal(w.Body.Bytes(), &reply)
	if w.Code != 200 || reply["status"] != "granted" || reply["grantId"] == "" || strings.Contains(w.Body.String(), "secret") || reply["url"] != "" {
		t.Fatal(w.Code, w.Body.String())
	}
	if tokenGrant(s, reply["grantId"], "files", "alice").Code != 200 {
		t.Fatal("reused account permission not usable")
	}
	if tokenGrant(s, reply["grantId"], "cloud-sync", "alice").Code != 403 {
		t.Fatal("cross-module access allowed")
	}
	w = request("unknown-scope")
	if w.Code != 403 {
		t.Fatal("module supplied unreviewed permission")
	}
	// A new reviewed capability still needs provider consent, not an existing token with different scopes.
	r := externalRequest("POST", "google/start", `{"purpose":"grant","connectionId":"connection","consumer":"cloud-sync","capability":"google-drive-readonly"}`)
	r.AddCookie(session)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var more map[string]any
	json.Unmarshal(w.Body.Bytes(), &more)
	if w.Code != 200 || more["url"] == nil {
		t.Fatal("missing permission must open consent", w.Body.String())
	}
}

func TestLinkCanAuthorizeFilesBeforeModulesExist(t *testing.T) {
	s, session := grantFixture(t)
	if err := s.Store.UnlinkExternal("alice", "connection"); err != nil {
		t.Fatal(err)
	}
	token, err := s.Store.Session("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Store.SessionDetails(token, 1000, "epoch", "", "test"); err != nil {
		t.Fatal(err)
	}
	session = &http.Cookie{Name: "panasms_session", Value: token}
	if err := os.WriteFile(filepath.Join(modules.Root, "registry.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	r := externalRequest("POST", "google/start", `{"purpose":"link","password":"test","fileAccess":true}`)
	r.AddCookie(session)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	done := finishGrant(s, session, w.Result().Cookies()[0])
	if done.Code != 200 {
		t.Fatal(done.Body.String())
	}
	owner, err := s.Store.ExternalOwner("google", "google-id")
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Store.AccountAuthorization(owner.ID, "https://www.googleapis.com/auth/drive")
	if err != nil || a.Token == nil {
		t.Fatal("account authorization not saved", err)
	}
	grants, err := s.Store.ExternalGrants("alice", 1000, "principal")
	if err != nil || len(grants) != 0 {
		t.Fatal("link silently granted a module access")
	}
}
