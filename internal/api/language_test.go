package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os/user"
	"panasms.local/backend/internal/auth"
	"strings"
	"testing"
)

func TestLanguagePreferenceValidationAndLegacyClient(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	s := testServer(t)
	s.Allowed[current.Username] = true
	id, err := auth.Lookup(current.Username, s.Allowed)
	if err != nil {
		t.Skip("requires a normal sudo test runner", err)
	}
	s.Agent = &http.Client{Transport: accountTestTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}
	token, err := s.Store.Session(current.Username)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Store.SessionDetails(token, id.UID, id.Epoch, "", "test"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		body     string
		status   int
		language string
	}{
		{`{"layouts":{},"theme":"dark","language":"uk"}`, 200, "uk"},
		{`{"layouts":{},"theme":"light"}`, 200, "uk"},
		{`{"layouts":{},"theme":"dark","language":"de"}`, 400, "uk"},
		{`{"layouts":{},"theme":"dark","language":"ru"}`, 200, "ru"},
		{`{"layouts":{},"theme":"dark","language":"en"}`, 200, "en"},
	} {
		r := httptest.NewRequest("PUT", "http://nas/api/v1/preferences", strings.NewReader(test.body))
		r.Header.Set("Origin", "http://nas")
		r.Header.Set("X-PaNasMs-Request", "1")
		r.AddCookie(&http.Cookie{Name: "panasms_session", Value: token})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%s: %d %s", test.body, w.Code, w.Body.String())
		}
		if p, err := s.Store.Preferences(current.Username); err != nil || p.Language != test.language {
			t.Fatal(p, err)
		}
	}
}

type accountTestTransport func(*http.Request) (*http.Response, error)

func (f accountTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
