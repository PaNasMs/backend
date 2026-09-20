package api

import (
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"ostojaos.local/backend/internal/auth"
	"ostojaos.local/backend/internal/modules"
	"strings"
)

func (s *Server) moduleAssets(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/v1/module-assets/"), "/", 2)
	if len(parts) != 2 || !modules.Enabled(parts[0]) {
		fail(w, 404, "Module unavailable")
		return
	}
	m := modules.Read()[parts[0]]
	rel := "ui/" + parts[1]
	if _, ok := m.Files[rel]; !ok || strings.Contains(rel, "..") {
		fail(w, 404, "File not found")
		return
	}
	path := filepath.Join(modules.Root, parts[0], rel)
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() {
		fail(w, 404, "File not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, path)
}
func (s *Server) moduleUpload(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	if id.Role != "admin" {
		fail(w, 403, "Administrator permissions required")
		return
	}
	req, e := http.NewRequestWithContext(r.Context(), "POST", "http://agent/module-upload?user="+url.QueryEscape(id.Username), http.MaxBytesReader(w, r.Body, 128<<20))
	if e != nil {
		fail(w, 400, "Invalid request")
		return
	}
	client := *s.Agent
	client.Timeout = 0
	resp, e := client.Do(req)
	if e != nil {
		fail(w, 503, "Could not upload archive")
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, 8192))
}
func (s *Server) moduleAPI(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	if id.Role != "admin" {
		fail(w, 403, "Administrator permissions required")
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if r.Header.Get("Origin") != scheme+"://"+r.Host {
			fail(w, 403, "Invalid request origin")
			return
		}
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/v1/module-api/"), "/", 2)
	if len(parts) != 2 || parts[0] == "files" || parts[0] == "terminal" {
		fail(w, 404, "Not found")
		return
	}
	client, e := modules.Client(parts[0])
	if e != nil {
		fail(w, 404, "Module disabled")
		return
	}
	proxy := httputil.ReverseProxy{Transport: client.Transport, Rewrite: func(p *httputil.ProxyRequest) {
		p.Out.URL.Scheme = "http"
		p.Out.URL.Host = "module"
		p.Out.URL.Path = "/" + parts[1]
		v := p.Out.URL.Query()
		v.Set("user", id.Username)
		p.Out.URL.RawQuery = v.Encode()
		p.Out.Header.Del("Cookie")
		p.Out.Header.Del("Authorization")
	}}
	proxy.ServeHTTP(w, r)
}
