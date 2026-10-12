package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/modules"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMemberModuleOptIn(t *testing.T) {
	old := modules.Root
	modules.Root = t.TempDir()
	defer func() { modules.Root = old }()
	registry := map[string]modules.Manifest{
		"file-drop":  {ID: "file-drop", Enabled: true, MemberAccess: true},
		"containers": {ID: "containers", Enabled: true},
	}
	raw, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(modules.Root, "registry.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	id := auth.Identity{Username: "alice", Role: "user"}
	for _, test := range []struct {
		path    string
		allowed bool
	}{
		{"module-api/file-drop/state", true}, {"module-assets/file-drop/index.js", true},
		{"module-api/containers/state", false}, {"module-assets/containers/index.js", false},
	} {
		r := httptest.NewRequest("GET", "/api/v1/"+test.path, nil)
		if got := userRoute(id, r); got != test.allowed {
			t.Fatalf("%s: got %t", test.path, got)
		}
	}
	server := &Server{ModuleClient: func(string) (*http.Client, error) {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Query().Get("user") != "alice" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
				t.Errorf("untrusted identity reached module: %s", r.URL)
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
		})}, nil
	}}
	for _, test := range []struct {
		path   string
		status int
	}{{"file-drop/state?user=bob", 200}, {"containers/state", 403}} {
		r := httptest.NewRequest("GET", "/api/v1/module-api/"+test.path, nil)
		r.Header.Set("Authorization", "Bearer ignored")
		r.Header.Set("Cookie", "ignored=value")
		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, id))
		w := httptest.NewRecorder()
		server.moduleAPI(w, r)
		if w.Code != test.status {
			t.Fatalf("%s: %d", test.path, w.Code)
		}
	}
}
