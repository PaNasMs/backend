package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/coder/websocket"
	"golang.org/x/sys/unix"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"panasms.local/backend/internal/auth"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var terminalCount atomic.Int32

func terminalHandler(allowed map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.Lookup(r.URL.Query().Get("user"), allowed)
		if err != nil {
			http.Error(w, "access denied", 403)
			return
		}
		if terminalCount.Add(1) > 8 {
			terminalCount.Add(-1)
			http.Error(w, "too many terminals", 429)
			return
		}
		defer terminalCount.Add(-1)
		u, err := user.Lookup(id.Username)
		if err != nil {
			http.Error(w, "user unavailable", 503)
			return
		}
		gid, _ := strconv.Atoi(u.Gid)
		groups, _ := u.GroupIds()
		gids := []uint32{}
		for _, g := range groups {
			v, e := strconv.Atoi(g)
			if e == nil {
				gids = append(gids, uint32(v))
			}
		}
		fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if err != nil {
			http.Error(w, "pty unavailable", 503)
			return
		}
		master := os.NewFile(uintptr(fd), "pty")
		defer master.Close()
		if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
			http.Error(w, "pty unavailable", 503)
			return
		}
		number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
		if err != nil {
			http.Error(w, "pty unavailable", 503)
			return
		}
		slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
		if err != nil {
			http.Error(w, "pty unavailable", 503)
			return
		}
		defer slave.Close()
		if err = os.Chown(slave.Name(), id.UID, gid); err != nil {
			http.Error(w, "pty unavailable", 503)
			return
		}
		unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80})
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer c.CloseNow()
		c.SetReadLimit(65536)
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		groupIDs := []string{}
		for _, g := range gids {
			groupIDs = append(groupIDs, strconv.Itoa(int(g)))
		}
		cmd := exec.Command("/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "--wd="+u.HomeDir, "--", "/usr/bin/setpriv", "--reuid", strconv.Itoa(id.UID), "--regid", strconv.Itoa(gid), "--groups", strings.Join(groupIDs, ","), "/bin/bash", "--login")
		cmd.Dir = u.HomeDir
		cmd.Env = []string{"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username, "TERM=xterm-256color", "LANG=C.UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"}
		cmd.Stdin = slave
		cmd.Stdout = slave
		cmd.Stderr = slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		if err = cmd.Start(); err != nil {
			c.Close(websocket.StatusInternalError, "terminal unavailable")
			return
		}
		slave.Close()
		log.Printf("terminal opened user=%s", id.Username)
		defer func() {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGHUP)
			cmd.Process.Kill()
			cmd.Wait()
			log.Printf("terminal closed user=%s", id.Username)
		}()
		go func() {
			buf := make([]byte, 8192)
			for {
				n, e := master.Read(buf)
				if n > 0 {
					cx, stop := context.WithTimeout(ctx, 5*time.Second)
					err := c.Write(cx, websocket.MessageBinary, buf[:n])
					stop()
					if err != nil {
						cancel()
						return
					}
				}
				if e != nil {
					cancel()
					return
				}
			}
		}()
		for {
			_, raw, e := c.Read(ctx)
			if e != nil {
				return
			}
			var msg struct {
				Type string `json:"type"`
				Data string `json:"data"`
				Rows uint16 `json:"rows"`
				Cols uint16 `json:"cols"`
			}
			if json.Unmarshal(raw, &msg) != nil {
				continue
			}
			if msg.Type == "input" {
				if _, e = master.Write([]byte(msg.Data)); e != nil {
					return
				}
			} else if msg.Type == "resize" && msg.Rows >= 2 && msg.Rows <= 300 && msg.Cols >= 10 && msg.Cols <= 500 {
				unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: msg.Rows, Col: msg.Cols})
			}
		}
	}
}
