package api

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"panasms.local/backend/internal/auth"
)

func (s *Server) powerControl(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	req, e := http.NewRequestWithContext(r.Context(), r.Method, "http://agent/power-control?user="+url.QueryEscape(id.Username), http.MaxBytesReader(w, r.Body, 4096))
	if e != nil {
		fail(w, 500, "Power control request error")
		return
	}
	client := *s.Agent
	client.Timeout = 45 * time.Second
	response, e := client.Do(req)
	if e != nil {
		fail(w, 503, "Power control settings unavailable")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		fail(w, response.StatusCode, strings.TrimSpace(string(raw)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, io.LimitReader(response.Body, 16384))
}
