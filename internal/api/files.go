package api

import (
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"ostojaos.local/backend/internal/auth"
	"ostojaos.local/backend/internal/modules"
	"strconv"
)

func (s *Server) files(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	factory := s.ModuleClient
	if factory == nil {
		factory = modules.Client
	}
	moduleClient, moduleErr := factory("files")
	if moduleErr != nil {
		fail(w, 404, "Module is not installed or is disabled")
		return
	}
	v := url.Values{"user": {id.Username}, "target": {r.URL.Query().Get("target")}}
	thumbnail := r.Method == "GET" && r.URL.Query().Get("thumbnail") == "1"
	if thumbnail {
		v.Set("thumbnail", "1")
	}
	w.Header().Set("Cache-Control", "no-store")
	req, e := http.NewRequestWithContext(r.Context(), r.Method, "http://agent/files?"+v.Encode(), r.Body)
	if e != nil {
		fail(w, 400, "Invalid request")
		return
	}
	req.ContentLength = r.ContentLength
	client := *moduleClient
	client.Timeout = 0
	resp, e := client.Do(req)
	if e != nil {
		fail(w, 503, "Transfer failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		fail(w, resp.StatusCode, "Access denied, file already exists, or transfer interrupted")
		return
	}
	if thumbnail {
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	} else if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(v.Get("target"))}))
	}
	if r.Method == "GET" {
		if resp.ContentLength < 0 {
			fail(w, 502, "Could not determine transfer size")
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	w.WriteHeader(resp.StatusCode)
	n, err := io.Copy(w, resp.Body)
	if err != nil || (r.Method == "GET" && n != resp.ContentLength) {
		panic(http.ErrAbortHandler)
	}
}
