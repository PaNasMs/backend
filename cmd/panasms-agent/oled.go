package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/oled"
)

func oledHandler(allowed map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, e := auth.LookupPanel(r.URL.Query().Get("user"), allowed)
		if e != nil || id.Role != "admin" {
			http.Error(w, "Administrator permissions required", 403)
			return
		}
		if r.Method == "PUT" {
			var cfg oled.Settings
			d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			d.DisallowUnknownFields()
			if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF || cfg.Validate() != nil {
				http.Error(w, "Invalid OLED settings", 400)
				return
			}
			raw, _ := json.Marshal(cfg)
			// Finish applying or restoring settings even if the browser disconnects.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 40*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "--", "/usr/lib/panasms/panasms-oled", "configure")
			cmd.Stdin = bytes.NewReader(raw)
			if output, err := cmd.CombinedOutput(); err != nil {
				message := strings.TrimSpace(string(output))
				if message == "" {
					message = "Could not apply OLED settings: " + err.Error()
				}
				http.Error(w, message, 503)
				return
			}
		} else if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		state, e := oled.Read()
		if e != nil {
			http.Error(w, "Could not read OLED settings", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	}
}
