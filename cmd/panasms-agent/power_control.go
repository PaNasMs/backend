package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/powercontrol"
)

func powerControlHandler(allowed map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, e := auth.LookupPanel(r.URL.Query().Get("user"), allowed)
		if e != nil || id.Role != "admin" {
			http.Error(w, "Administrator permissions required", 403)
			return
		}
		if r.Method == "PUT" {
			cfg, err := powercontrol.Decode(http.MaxBytesReader(w, r.Body, 4096))
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			raw, _ := json.Marshal(cfg)
			// Finish applying or restoring settings even if the browser disconnects.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 40*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "--", "/usr/lib/panasms/panasms-system-helper", "power-control", "configure")
			cmd.Stdin = bytes.NewReader(raw)
			if output, err := cmd.CombinedOutput(); err != nil {
				message := strings.TrimSpace(string(output))
				if message == "" {
					message = "Could not apply power control settings: " + err.Error()
				}
				status := 503
				if message == powercontrol.ErrConflict.Error() {
					status = 409
				}
				http.Error(w, message, status)
				return
			}
		} else if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		state, e := powercontrol.Read()
		if e != nil {
			http.Error(w, "Could not read power control settings", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	}
}
