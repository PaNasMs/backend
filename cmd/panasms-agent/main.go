package main

import (
	"context"
	"encoding/json"
	"flag"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/cooling"
	"panasms.local/backend/internal/management"
	"strconv"
	"syscall"
	"time"
)

func main() {
	socket := flag.String("socket", "/run/panasms-agent/agent.sock", "Unix socket")
	peer := flag.Int("peer-uid", -1, "required core UID")
	peerGID := flag.Int("peer-gid", -1, "required core GID")
	flag.Parse()
	if *peer < 0 || *peerGID < 0 {
		log.Fatal("peer-uid required")
	}
	allowed, policyErr := auth.AccessPolicy(os.Getenv("PANASMS_AUTH_MODE"), os.Getenv("PANASMS_ALLOWED_USERS"))
	if policyErr != nil {
		log.Fatal(policyErr)
	}

	if _, err := os.Lstat(*socket); err == nil {
		log.Fatal("socket already exists; inspect and remove stale socket")
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: *socket, Net: "unix"})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	defer os.Remove(*socket)
	if err = os.Chown(*socket, 0, *peerGID); err != nil {
		log.Fatal(err)
	}
	if err = os.Chmod(*socket, 0660); err != nil {
		log.Fatal(err)
	}
	manager, err := management.Open("/var/lib/panasms-agent/jobs.db")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /job-feed", func(w http.ResponseWriter, r *http.Request) {
		jobs, e := manager.Monitor(r.URL.Query()["alert"])
		if e != nil {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jobs)
	})
	mux.HandleFunc("/manage", manager.Handler(allowed))
	mux.HandleFunc("POST /module-upload", moduleUpload(allowed))
	mux.HandleFunc("/profile", profileHandler(allowed))
	mux.HandleFunc("POST /authenticate", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if dec.Decode(&body) != nil || body.Username == "" || body.Password == "" {
			http.Error(w, "invalid request", 400)
			return
		}
		id, err := auth.Lookup(body.Username, allowed)
		if err != nil || auth.Authenticate(body.Username, body.Password) != nil {
			http.Error(w, "authentication failed", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(id)
	})

	mux.HandleFunc("/cooling", func(w http.ResponseWriter, r *http.Request) {
		if _, err := auth.Lookup(r.URL.Query().Get("user"), allowed); err != nil {
			http.Error(w, "access denied", 403)
			return
		}
		if r.Method == "PUT" {
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			var cfg cooling.Settings
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF || cooling.Validate(cfg) != nil {
				http.Error(w, "invalid cooling settings", 400)
				return
			}
			if cooling.Save(cfg) != nil {
				http.Error(w, "cooling configuration unavailable", 503)
				return
			}
		} else if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		state, err := cooling.Read()
		if err != nil {
			http.Error(w, "cooling controller unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 0, WriteTimeout: 0, IdleTimeout: 15 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		closeCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		srv.Shutdown(closeCtx)
	}()
	log.Print("agent ready; core UID=" + strconv.Itoa(*peer))
	if err := srv.Serve(&peerListener{UnixListener: l, uid: uint32(*peer)}); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

type peerListener struct {
	*net.UnixListener
	uid uint32
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			return nil, e
		}
		raw, e := c.SyscallConn()
		if e != nil {
			c.Close()
			continue
		}
		var cred *unix.Ucred
		var ce error
		e = raw.Control(func(fd uintptr) { cred, ce = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
		if e != nil || ce != nil || cred == nil || cred.Uid != l.uid {
			c.Close()
			continue
		}
		return c, nil
	}
}
