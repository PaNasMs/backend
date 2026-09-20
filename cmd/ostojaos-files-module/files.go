package main

import (
	"bufio"
	"context"
	"net/http"
	"os/exec"
	"ostojaos.local/backend/internal/auth"
	"ostojaos.local/backend/internal/transfer"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var thumbnailSlots = make(chan struct{}, 2)

func filesHandler(allowed map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, e := auth.Lookup(r.URL.Query().Get("user"), allowed)
		if e != nil {
			http.Error(w, "access denied", 403)
			return
		}
		mode := "download"
		if r.Method == "PUT" {
			mode = "upload"
		} else if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		ctx := r.Context()
		if r.Method == "GET" && r.URL.Query().Get("thumbnail") == "1" {
			mode = "thumbnail"
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			select {
			case thumbnailSlots <- struct{}{}:
				defer func() { <-thumbnailSlots }()
			case <-ctx.Done():
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		target := r.URL.Query().Get("target")
		if len(target) > 1024 {
			w.WriteHeader(400)
			return
		}
		cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "--", "/usr/bin/python3", "-B", "/var/lib/ostojaos-modules/files/backend/operations.py", mode, id.Username, target, strconv.FormatInt(r.ContentLength, 10))
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = 5 * time.Second
		if mode == "upload" {
			if r.ContentLength < 0 {
				w.WriteHeader(411)
				return
			}
			cmd.Stdin = r.Body
			if e = cmd.Run(); e != nil {
				http.Error(w, "upload failed or file already exists", 409)
				return
			}
			w.WriteHeader(204)
			return
		}
		pipe, e := cmd.StdoutPipe()
		if e != nil {
			w.WriteHeader(503)
			return
		}
		if e = cmd.Start(); e != nil {
			w.WriteHeader(503)
			return
		}
		waited := false
		defer func() {
			if !waited {
				cmd.Wait()
			}
		}()
		defer pipe.Close()
		reader := bufio.NewReader(pipe)
		line, e := reader.ReadSlice('\n')
		size, sizeErr := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(string(line), "OK "), "\n"), 10, 64)
		if e != nil || !strings.HasPrefix(string(line), "OK ") || sizeErr != nil || size < 0 {
			w.WriteHeader(403)
			return
		}
		if mode == "thumbnail" {
			w.Header().Set("Content-Type", "image/jpeg")
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		transfer.Stream(w, reader, size, func() error { waited = true; return cmd.Wait() })
	}
}
