package webaccess

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	s := Default()
	s.Config = filepath.Join(dir, "web.env")
	s.StatePath = filepath.Join(dir, "state.json")
	s.Lock = filepath.Join(dir, "lock")
	s.Write = func(p, body string, mode os.FileMode) error { return os.WriteFile(p, []byte(body), mode) }
	s.Available = func(int) error { return nil }
	s.Healthy = func(int) bool { return true }
	s.Sleep = func(time.Duration) {}
	s.Run = func([]string) error { return nil }
	return s
}
func TestPortValidation(t *testing.T) {
	for _, v := range []any{true, "80", json.Number("80.0"), json.Number("8e1"), 0, 65536, 22, 6667} {
		if _, err := Port(v); err == nil {
			t.Fatalf("accepted %#v", v)
		}
	}
	if p, err := Port(json.Number("8080")); err != nil || p != 8080 {
		t.Fatal(p, err)
	}
}
func TestPlanAndDeferredApply(t *testing.T) {
	s := fixture(t)
	p := map[string]any{"port": json.Number("8080")}
	plan, err := s.Plan("system.web-port", p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plan), `"confirmation":"8080"`) {
		t.Fatal(string(plan))
	}
	calls := [][]string{}
	s.Run = func(a []string) error { calls = append(calls, a); return nil }
	if _, err := s.Execute(p); err != nil {
		t.Fatal(err)
	}
	if current, _ := s.Current(); current != 80 {
		t.Fatal("changed before timer")
	}
	if !strings.Contains(strings.Join(calls[0], " "), "panasms-system-helper web-access --apply") {
		t.Fatal(calls)
	}
	if _, err := s.Plan("system.web-port", p); err == nil {
		t.Fatal("accepted pending change")
	}
	if err := s.Apply(); err != nil {
		t.Fatal(err)
	}
	st, _ := s.state()
	if st.Phase != "ready" {
		t.Fatal(st)
	}
	if current, _ := s.Current(); current != 8080 {
		t.Fatal(current)
	}
}
func TestApplyFailureRestoresPreviousPort(t *testing.T) {
	for _, failure := range []string{"busy", "restart", "health"} {
		t.Run(failure, func(t *testing.T) {
			s := fixture(t)
			if _, err := s.Execute(map[string]any{"port": json.Number("8080")}); err != nil {
				t.Fatal(err)
			}
			restarts := 0
			s.Run = func([]string) error {
				restarts++
				if failure == "restart" && restarts == 1 {
					return errors.New("failed")
				}
				return nil
			}
			s.Available = func(int) error {
				if failure == "busy" {
					return errors.New("busy")
				}
				return nil
			}
			s.Healthy = func(int) bool { return failure != "health" }
			if err := s.Apply(); err == nil {
				t.Fatal("accepted failure")
			}
			current, _ := s.Current()
			st, _ := s.state()
			if current != 80 || st.Phase != "failed" || st.Error == "" || restarts < 1 {
				t.Fatal(current, st, restarts)
			}
		})
	}
}
func TestRecoveryAndConfigure(t *testing.T) {
	s := fixture(t)
	for _, phase := range []string{"scheduled", "applying"} {
		if err := s.save(State{Phase: phase, Previous: 80, Port: 8080}); err != nil {
			t.Fatal(err)
		}
		if err := s.writePort(8080); err != nil {
			t.Fatal(err)
		}
		if err := s.Recover(); err != nil {
			t.Fatal(err)
		}
		if p, _ := s.Current(); p != 80 {
			t.Fatal(p)
		}
	}
	if p, err := s.Configure(8081); err != nil || p != 8081 {
		t.Fatal(p, err)
	}
	if p, err := s.Configure(nil); err != nil || p != 8081 {
		t.Fatal(p, err)
	}
}
func TestScheduleFailureAndNoOp(t *testing.T) {
	s := fixture(t)
	s.Run = func([]string) error { return errors.New("timer failed") }
	if _, err := s.Execute(map[string]any{"port": json.Number("80")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Execute(map[string]any{"port": json.Number("8080")}); err == nil {
		t.Fatal("timer failed silently")
	}
	if _, err := os.Stat(s.StatePath); !os.IsNotExist(err) {
		t.Fatal("pending state remained", err)
	}
}

func TestLivePortConflictAndHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health" {
			t.Error(r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()
	_, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	if err := available(port); err == nil {
		t.Fatal("occupied port accepted")
	}
	if !healthy(port) {
		t.Fatal("health probe failed")
	}
	server.Close()
	if healthy(port) {
		t.Fatal("closed listener considered healthy")
	}
}

func TestHealthRejectsErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503); io.WriteString(w, `{"status":"ok"}`) }))
	defer server.Close()
	_, text, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(text)
	if healthy(port) {
		t.Fatal("accepted HTTP error as healthy")
	}
}
