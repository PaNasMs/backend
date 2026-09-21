package api

import (
	"context"
	"net/http/httptest"
	"panasms.local/backend/internal/auth"
	"strings"
	"testing"
)

func TestOrdinaryUserRouteBoundary(t *testing.T) {
	user := auth.Identity{Username: "alice", Role: "user"}
	for _, test := range []struct {
		method, path string
		allowed      bool
	}{
		{"GET", "users", false}, {"GET", "network", false}, {"POST", "power", false}, {"PUT", "cooling", false},
		{"GET", "terminal", false}, {"GET", "module-assets/terminal/main.js", false}, {"GET", "manage?view=accounts", false},
		{"GET", "manage?view=network", false}, {"GET", "manage?view=module-catalog", false},
		{"GET", "profile", true}, {"POST", "profile", true}, {"GET", "sessions", true}, {"GET", "metrics", true},
		{"GET", "manage?view=files", true}, {"GET", "module-assets/files/main.js", true}, {"POST", "manage", true},
	} {
		r := httptest.NewRequest(test.method, "/api/v1/"+test.path, nil)
		if userRoute(user, r) != test.allowed {
			t.Fatal(test)
		}
	}
}
func TestSessionEndpointRejectsOtherUser(t *testing.T) {
	s := testServer(t)
	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, "/api/v1/sessions?user=bob", strings.NewReader(`{"id":"anything"}`))
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, auth.Identity{Username: "alice", Role: "user"}))
		w := httptest.NewRecorder()
		s.sessions(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
}
