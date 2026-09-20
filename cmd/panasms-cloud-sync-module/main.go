package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/modulehost"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const stateRoot = "/var/lib/panasms-cloud-sync"

var busy atomic.Int32
var workerMu sync.Mutex
var workers = map[string]bool{}
var script string

func process(ctx context.Context, account *user.User, mode string) (*exec.Cmd, error) {
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid == 0 {
		return nil, fmt.Errorf("invalid user")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(stateRoot, account.Uid)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err = os.Chown(dir, uid, gid); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--collect", "--wait", "--pipe",
		"--unit=panasms-cloud-sync-user-"+account.Uid,
		"--uid="+account.Uid, "--gid="+account.Gid,
		"--property=BindsTo=panasms-module-cloud-sync.service",
		"--property=After=panasms-module-cloud-sync.service",
		"--property=KillMode=control-group", "--property=UMask=0077", "--property=NoNewPrivileges=yes",
		"--setenv=HOME="+dir, "--setenv=XDG_CACHE_HOME="+dir+"/cache", "--setenv=LANG=C.UTF-8",
		"/usr/bin/python3", "-B", script, mode, dir)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	return cmd, nil
}
func startWorker(account *user.User) {
	workerMu.Lock()
	defer workerMu.Unlock()
	if workers[account.Uid] {
		return
	}
	workers[account.Uid] = true
	go func() {
		defer func() { workerMu.Lock(); delete(workers, account.Uid); workerMu.Unlock() }()
		cmd, err := process(context.Background(), account, "worker")
		if err != nil {
			return
		}
		pipe, err := cmd.StdoutPipe()
		if err != nil {
			return
		}
		if err = cmd.Start(); err != nil {
			return
		}
		running := false
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			var event struct {
				Busy bool `json:"busy"`
			}
			if json.Unmarshal(scanner.Bytes(), &event) == nil && event.Busy != running {
				running = event.Busy
				if running {
					busy.Add(1)
				} else {
					busy.Add(-1)
				}
			}
		}
		if running {
			busy.Add(-1)
		}
		_ = cmd.Wait()
	}()
}
func respond(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
func main() {
	executable, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	script = filepath.Join(filepath.Dir(executable), "../backend/cloud_sync.py")
	if err = os.MkdirAll(stateRoot, 0711); err != nil {
		log.Fatal(err)
	}
	if err = os.Chmod(stateRoot, 0711); err != nil {
		log.Fatal(err)
	}
	modulehost.ServeWithActivity("cloud-sync", func() int32 { return busy.Load() }, func(allowed map[string]bool) http.Handler {
		go func() {
			for {
				dirs, _ := os.ReadDir(stateRoot)
				for _, dir := range dirs {
					if !dir.IsDir() {
						continue
					}
					account, e := user.LookupId(dir.Name())
					if e != nil {
						continue
					}
					id, e := auth.Lookup(account.Username, allowed)
					if e == nil && id.Role == "admin" {
						startWorker(account)
					}
				}
				time.Sleep(10 * time.Second)
			}
		}()
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, e := auth.Lookup(r.URL.Query().Get("user"), allowed)
			if e != nil || identity.Role != "admin" {
				respond(w, 403, "Administrator permissions required")
				return
			}
			account, e := user.Lookup(identity.Username)
			if e != nil {
				respond(w, 403, "Account unavailable")
				return
			}
			if r.URL.Path != "/state" && r.URL.Path != "/action" && r.URL.Path != "/authorize-helper" {
				respond(w, 404, "Not found")
				return
			}
			if r.URL.Path == "/authorize-helper" && r.Method == "GET" {
				w.Header().Set("Content-Disposition", `attachment; filename="panasms-cloud-authorize.py"`)
				http.ServeFile(w, r, filepath.Join(filepath.Dir(script), "authorize.py"))
				return
			}
			if (r.URL.Path == "/state" && r.Method != "GET") || (r.URL.Path == "/action" && r.Method != "POST") {
				respond(w, 405, "Method not allowed")
				return
			}
			mode := "state"
			var params json.RawMessage
			if r.URL.Path == "/action" {
				mode = "action"
				data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
				if err != nil || !json.Valid(data) {
					respond(w, 400, "Invalid request")
					return
				}
				params = data
			}
			startWorker(account)
			var conn net.Conn
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				conn, e = net.DialTimeout("unix", filepath.Join(stateRoot, account.Uid, "worker.sock"), 250*time.Millisecond)
				if e == nil {
					break
				}
				select {
				case <-r.Context().Done():
					return
				case <-time.After(100 * time.Millisecond):
				}
			}
			if e != nil {
				respond(w, 503, "Cloud Sync worker is unavailable")
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(150 * time.Second))
			e = json.NewEncoder(conn).Encode(struct {
				Mode   string          `json:"mode"`
				Params json.RawMessage `json:"params"`
			}{mode, params})
			if e != nil {
				respond(w, 503, "Cloud Sync request failed")
				return
			}
			out, e := bufio.NewReader(io.LimitReader(conn, 4<<20)).ReadBytes('\n')
			if e != nil || !json.Valid(out) {
				respond(w, 503, "Cloud Sync request failed")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(out)
			startWorker(account)
		})
	})
}
