package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"ostojaos.local/backend/internal/auth"
	"ostojaos.local/backend/internal/store"
	"testing"
	"time"
)

func TestBrowserHarness(t *testing.T) {
	dir := os.Getenv("OSTOJAOS_SMOKE_DIR")
	if dir == "" {
		t.Skip("manual browser integration harness")
	}
	user := os.Getenv("USER")
	allowed := map[string]bool{user: true}
	if _, e := auth.Lookup(user, allowed); e != nil {
		t.Fatal(e)
	}
	db, e := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	static, e := filepath.Abs("../../../frontend/dist")
	if e != nil {
		t.Fatal(e)
	}
	app := New(db, "/nonexistent", static, allowed, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go app.Run(ctx)
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	token, e := db.Session(user)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(map[string]string{"url": srv.URL, "token": token})
	if e = os.WriteFile(filepath.Join(dir, "connection.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-timer.C:
			t.Fatal("browser smoke timed out")
		case <-tick.C:
			if _, e := os.Stat(filepath.Join(dir, "done")); e == nil {
				return
			}
		}
	}
}
