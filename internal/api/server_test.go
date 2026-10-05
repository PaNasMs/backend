package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/store"
	"panasms.local/backend/internal/system"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	db, e := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	return New(db, "/nonexistent", t.TempDir(), map[string]bool{}, false)
}
func TestProtectedEndpoints(t *testing.T) {
	s := testServer(t)
	for _, p := range []string{"wallpaper", "wallpaper/image", "session", "users", "storage", "metrics", "preferences", "events", "cooling", "profile", "manage", "terminal", "files/content", "metrics/history"} {
		r := httptest.NewRequest("GET", "/api/v1/"+p, nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
}
func TestMaintenanceAllowsPassiveEventsButBlocksOperations(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "maintenance")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	t.Setenv("PANASMS_MAINTENANCE_LOCK", file.Name())
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	s := testServer(t)
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", "events", 401},
		{"GET", "module-api/containers/events", 401},
		{"POST", "module-api/containers/events", 503},
		{"GET", "module-api/containers/jobs", 503},
		{"POST", "module-api/containers/action", 503},
		{"GET", "module-api/other/events", 503},
		{"GET", "terminal", 503},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(tc.method, "/api/v1/"+tc.path, nil))
		if w.Code != tc.status {
			t.Errorf("%s %s: got %d, want %d", tc.method, tc.path, w.Code, tc.status)
		}
	}
}
func TestCSRF(t *testing.T) {
	s := testServer(t)
	for _, origin := range []string{"", "http://evil.test"} {
		r := httptest.NewRequest("POST", "http://nas/api/v1/login", strings.NewReader(`{"username":"a","password":"b"}`))
		r.Header.Set("Origin", origin)
		r.Header.Set("X-PaNasMs-Request", "1")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
}
func TestAgentUnavailableFailsClosed(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("POST", "http://nas/api/v1/login", strings.NewReader(`{"username":"a","password":"b"}`))
	r.Header.Set("Origin", "http://nas")
	r.Header.Set("X-PaNasMs-Request", "1")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 503 || len(w.Result().Cookies()) != 0 {
		t.Fatal(w.Code)
	}
}
func TestCookieAndRateLimit(t *testing.T) {
	s := testServer(t)
	s.Secure = true
	w := httptest.NewRecorder()
	s.cookie(w, "token", 3600)
	c := w.Result().Cookies()[0]
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	for i := 0; i < 5; i++ {
		if !s.permit("host") {
			t.Fatal("early throttle")
		}
	}
	if s.permit("host") {
		t.Fatal("missing throttle")
	}
}
func TestCollectorsReadRealLinux(t *testing.T) {
	c := &system.Collector{}
	if _, e := c.Read(); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, e := system.AccountsRead(ctx)
	if e != nil || len(a.Users) == 0 {
		t.Fatal(e)
	}
	s, e := system.StorageRead(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if s.ObservedAt.IsZero() {
		t.Fatal("missing observation timestamp")
	}
}

func TestUnknownAPIAndMalformedBody(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("GET", "/api/v1/unknown", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, body := range []string{`{"username":"a","password":"b","extra":true}`, `{"username":"a","password":"b"} {}`} {
		r = httptest.NewRequest("POST", "http://nas/api/v1/login", strings.NewReader(body))
		r.Header.Set("Origin", "http://nas")
		r.Header.Set("X-PaNasMs-Request", "1")
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
}

func TestDesktopRejectsOverlapAndOutOfBounds(t *testing.T) {
	valid := map[string][]store.DesktopTile{"mobile": {{ID: "a", Kind: "cpu", X: 0, Y: 0}, {ID: "b", Kind: "users", X: 0, Y: 2}}}
	if !validDesktop(valid) {
		t.Fatal("valid layout rejected")
	}
	valid["mobile"][1].Y = 1
	if validDesktop(valid) {
		t.Fatal("overlap accepted")
	}
	valid["mobile"][1].Y = 2
	valid["mobile"][1].X = 2
	if validDesktop(valid) {
		t.Fatal("out of bounds accepted")
	}
}

func TestTaskbarPreferences(t *testing.T) {
	if !validTaskbar(nil) {
		t.Fatal("legacy preferences rejected")
	}
	for _, ids := range [][]string{{}, {"files", "users", "settings", "history"}} {
		if !validTaskbar(&ids) {
			t.Fatal("valid taskbar rejected", ids)
		}
	}
	for _, ids := range [][]string{{"files", "files"}, {"unknown"}} {
		if validTaskbar(&ids) {
			t.Fatal("invalid taskbar accepted", ids)
		}
	}
	for _, kind := range []string{"app-settings", "app-terminal", "app-system", "app-sharing", "app-history"} {
		if !validDesktop(map[string][]store.DesktopTile{"mobile": {{ID: "shortcut", Kind: kind}}}) {
			t.Fatal("shortcut rejected", kind)
		}
	}
}

func TestPreferencesBodyFitsSupportedLimits(t *testing.T) {
	p := store.Preferences{Theme: "dark", SmartCrcBaselines: map[string]uint64{}}
	for i := 0; i < 256; i++ {
		p.SmartCrcBaselines[fmt.Sprintf("%03d", i)+strings.Repeat("x", 509)] = 42
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got store.Preferences
	if !decodeLimit(httptest.NewRecorder(), httptest.NewRequest("PUT", "/", strings.NewReader(string(raw))), &got, 1<<20) {
		t.Fatal("supported preferences rejected")
	}
	if len(got.SmartCrcBaselines) != 256 {
		t.Fatal("settings lost")
	}
	if decode(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(string(raw))), &got) {
		t.Fatal("login body limit expanded")
	}
}

func TestTileSizesCoverModuleWidgets(t *testing.T) {
	for kind, want := range map[string][2]int{"app-network": {1, 1}, "clock": {2, 1}, "cpu": {2, 2}, "hddCooling": {2, 2}, "network": {2, 2}, "disks": {2, 2}, "users": {1, 1}} {
		if size, ok := tileSize(kind); !ok || size != want {
			t.Fatalf("%s: %v %v", kind, size, ok)
		}
	}
	if _, ok := tileSize("unknown-widget"); ok {
		t.Fatal("unknown kind accepted")
	}
}

func TestPerDiskWidgetKeys(t *testing.T) {
	for _, kind := range []string{"disk-temp:WD-WXN1A58EJUUC", "disk-temp:sda", "disk-temp:S3Z2NB0K.123_x-1"} {
		size, ok := tileSize(kind)
		if !ok || size != [2]int{2, 1} {
			t.Fatalf("%s rejected: %v %v", kind, size, ok)
		}
	}
	for _, kind := range []string{"disk-temp:", "disk-temp:../etc", "disk-temp:a b", "disk-temp:" + strings.Repeat("x", 65), "disk-temp:диск"} {
		if _, ok := tileSize(kind); ok {
			t.Fatalf("%q accepted", kind)
		}
	}
}

func TestDesktopAcceptsMixedSizes(t *testing.T) {
	layout := map[string][]store.DesktopTile{"wide": {
		{ID: "a", Kind: "cpu", X: 0, Y: 0},
		{ID: "b", Kind: "network", X: 2, Y: 0},
		{ID: "c", Kind: "clock", X: 5, Y: 0},
		{ID: "d", Kind: "disk-temp:WD-1", X: 5, Y: 1},
	}}
	if !validDesktop(layout) {
		t.Fatal("mixed sizes rejected")
	}
	// Часы не должны перекрывать соседний виджет.
	layout["wide"][2].X = 3
	if validDesktop(layout) {
		t.Fatal("overlap between widgets of different size accepted")
	}
}

func TestNetworkTaskbarPreference(t *testing.T) {
	ids := []string{"network", "storage"}
	if !validTaskbar(&ids) {
		t.Fatal("network shortcut rejected")
	}
}

func TestLimiterCapacityDoesNotLockOutAllUsers(t *testing.T) {
	s := testServer(t)
	for i := 0; i < 1024; i++ {
		if !s.permit(fmt.Sprint(i)) {
			t.Fatal("initial request rejected")
		}
	}
	if !s.permit("new-user") {
		t.Fatal("full map blocked a new user")
	}
	if len(s.attempts) != 1024 {
		t.Fatalf("unbounded limiter: %d", len(s.attempts))
	}
	for i := 0; i < 4; i++ {
		if !s.permit("new-user") {
			t.Fatal("early rejection")
		}
	}
	if s.permit("new-user") {
		t.Fatal("per-key limit bypassed")
	}
	if !s.permit("another-user") {
		t.Fatal("one user's limit blocks others")
	}
}

func TestIdentityUsesAgentAndChecksSessionEpoch(t *testing.T) {
	s := testServer(t)
	token, err := s.Store.Session("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.SessionDetails(token, 1000, "epoch", "", "test"); err != nil {
		t.Fatal(err)
	}
	s.lookupIdentity = func(string, map[string]bool) (auth.Identity, error) {
		t.Fatal("duplicate OS lookup")
		return auth.Identity{}, nil
	}
	epoch := "epoch"
	s.Agent = &http.Client{Transport: identityTransport(func(r *http.Request) (*http.Response, error) {
		raw := fmt.Sprintf(`{"username":"alice","uid":1000,"role":"user","epoch":%q}`, epoch)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw)), Header: http.Header{}}, nil
	})}
	req := httptest.NewRequest("GET", "/api/v1/session", nil)
	req.AddCookie(&http.Cookie{Name: "panasms_session", Value: token})
	if _, err := s.Identity(req); err != nil {
		t.Fatal(err)
	}
	epoch = "revoked"
	if _, err := s.Identity(req); err == nil {
		t.Fatal("revoked session accepted")
	}
}

type identityTransport func(*http.Request) (*http.Response, error)

func (f identityTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestInterfacePageIsRevalidatedAndAssetsAreCached(t *testing.T) {
	s := testServer(t)
	s.Static = t.TempDir()
	if err := os.MkdirAll(filepath.Join(s.Static, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"index.html": "<html></html>", "assets/index-abc.js": "x"} {
		if err := os.WriteFile(filepath.Join(s.Static, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := s.Handler()
	for path, want := range map[string]string{
		"/":                    "no-cache",
		"/storage/disks":       "no-cache",
		"/index.html":          "no-cache",
		"/assets/index-abc.js": "public, max-age=31536000, immutable",
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if got := w.Header().Get("Cache-Control"); got != want {
			t.Errorf("%s: Cache-Control %q, want %q", path, got, want)
		}
	}
}
