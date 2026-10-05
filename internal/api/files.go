package api

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/modules"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	if revision := r.URL.Query().Get("replace_revision"); r.Method == "PUT" && revision != "" {
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(revision) {
			fail(w, 400, "Invalid replacement revision")
			return
		}
		v.Set("replace_revision", revision)
	}
	thumbnail := r.Method == "GET" && r.URL.Query().Get("thumbnail") == "1"
	if thumbnail {
		v.Set("thumbnail", "1")
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == "GET" && !thumbnail && strings.HasPrefix(v.Get("target"), "cloud:") {
		if link := directLink(r.Context(), moduleClient, v); link != "" {
			// The browser fetches the file from the provider; nothing passes through the NAS.
			w.Header().Set("Referrer-Policy", "no-referrer")
			http.Redirect(w, r, link, http.StatusFound)
			return
		}
	}
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

// directLink asks the Files module for a short-lived provider link to a cloud file. It returns ""
// when the provider has none or the module predates the feature; the caller then streams the file.
func directLink(ctx context.Context, moduleClient *http.Client, v url.Values) string {
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	query := url.Values{"user": v["user"], "target": v["target"], "direct": {"1"}}
	req, e := http.NewRequestWithContext(ctx, "GET", "http://agent/files?"+query.Encode(), nil)
	if e != nil {
		return ""
	}
	resp, e := moduleClient.Do(req)
	if e != nil {
		return ""
	}
	// An older module ignores direct=1 and starts sending the file: drop that response unread.
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return ""
	}
	var reply struct {
		URL string `json:"url"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&reply) != nil || !trustedDownloadLink(reply.URL) {
		return ""
	}
	return reply.URL
}

// trustedDownloadLink accepts only Dropbox temporary content links as redirect targets.
func trustedDownloadLink(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "dl.dropboxusercontent.com" || strings.HasSuffix(host, ".dl.dropboxusercontent.com")
}
