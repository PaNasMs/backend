package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"panasms.local/backend/internal/auth"
	"time"
)

func moduleUpload(allowed map[string]bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, e := auth.Lookup(r.URL.Query().Get("user"), allowed)
		if e != nil || id.Role != "admin" {
			http.Error(w, "access denied", 403)
			return
		}
		root := "/var/lib/panasms-agent/module-uploads"
		if os.MkdirAll(root, 0700) != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		entries, _ := os.ReadDir(root)
		for _, entry := range entries {
			info, e := entry.Info()
			if e == nil && time.Since(info.ModTime()) > 24*time.Hour {
				os.Remove(filepath.Join(root, entry.Name()))
			}
		}
		entries, _ = os.ReadDir(root)
		if len(entries) >= 16 {
			http.Error(w, "Too many uploaded archives; remove old ones or try again later", 429)
			return
		}
		token := make([]byte, 16)
		rand.Read(token)
		key := hex.EncodeToString(token)
		path := filepath.Join(root, id.Username+"-"+key+".zip")
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		size, e := io.Copy(f, http.MaxBytesReader(w, r.Body, 128<<20))
		closeErr := f.Close()
		if e != nil || closeErr != nil || size == 0 {
			os.Remove(path)
			http.Error(w, "Archive is empty or exceeds 128 MiB", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"upload": key})
	}
}
