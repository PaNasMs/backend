package api

import (
	"net/http"
	"net/http/httptest"
	"os/user"
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
	token, err := s.Store.Session(current.Username)
	if err != nil {
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
