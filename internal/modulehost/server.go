package modulehost

import (
	"encoding/json"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/modules"
	"strconv"
	"sync/atomic"
)

type peers struct {
	*net.UnixListener
	uid uint32
}

func (p *peers) Accept() (net.Conn, error) {
	for {
		c, e := p.AcceptUnix()
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
		if e != nil || ce != nil || cred == nil || (cred.Uid != p.uid && cred.Uid != 0) {
			c.Close()
			continue
		}
		return c, nil
	}
}
func Serve(id string, build func(map[string]bool) http.Handler) {
	ServeWithActivity(id, func() int32 { return 0 }, build)
}

func ServeWithActivity(id string, activity func() int32, build func(map[string]bool) http.Handler) {
	account, e := user.Lookup("panasms")
	if e != nil {
		log.Fatal(e)
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	allowed, e := auth.AccessPolicy(os.Getenv("PANASMS_AUTH_MODE"), os.Getenv("PANASMS_ALLOWED_USERS"))
	if e != nil {
		log.Fatal(e)
	}
	path := "/run/panasms-modules/" + id + ".sock"
	if e = os.Remove(path); e != nil && !os.IsNotExist(e) {
		log.Fatal(e)
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		log.Fatal(e)
	}
	defer os.Remove(path)
	os.Chown(path, 0, gid)
	os.Chmod(path, 0660)
	handler := build(allowed)
	var active atomic.Int32
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			json.NewEncoder(w).Encode(map[string]int32{"active": active.Load() + activity()})
			return
		}
		active.Add(1)
		defer active.Add(-1)
		if !modules.Enabled(id) {
			http.Error(w, "module disabled", 404)
			return
		}
		handler.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 5e9}
	log.Fatal(srv.Serve(&peers{listener, uint32(uid)}))
}
