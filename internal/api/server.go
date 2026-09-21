package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/coder/websocket"
	"github.com/go-chi/chi/v5"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/cooling"
	"panasms.local/backend/internal/modules"
	"panasms.local/backend/internal/store"
	"panasms.local/backend/internal/system"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Server struct {
	ModuleClient          func(string) (*http.Client, error)
	Store                 *store.Store
	Agent                 *http.Client
	Allowed               map[string]bool
	Secure                bool
	Static                string
	metricsMu             sync.RWMutex
	metrics               system.Metrics
	metricsError          bool
	jobsRevision          atomic.Value
	notificationsRevision atomic.Value
	knownDevices          map[string]deviceSnapshot
	seenEjects            map[string]bool
	revision              atomic.Uint64
	limitMu               sync.Mutex
	attempts              map[string][]time.Time
}

func New(db *store.Store, socket, static string, allowed map[string]bool, secure bool) *Server {
	t := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &Server{ModuleClient: modules.Client, Store: db, Agent: &http.Client{Transport: t, Timeout: 15 * time.Second}, Allowed: allowed, Secure: secure, Static: static, attempts: map[string][]time.Time{}}
}
func (s *Server) Run(ctx context.Context) {
	collector := &system.Collector{}
	collect := func() {
		m, e := collector.Read()
		s.metricsMu.Lock()
		s.metrics = m
		s.metricsError = e != nil
		s.metricsMu.Unlock()
		if e == nil {
			s.Store.RecordMetrics(m)
			s.monitor(ctx, m)
		}
	}
	collect()
	go system.Watch(ctx, func(_ string) { s.revision.Add(1) })
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collect()
		}
	}
}
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeLimit(w, r, v, 16384)
}
func decodeLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		fail(w, 400, "Invalid request")
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		fail(w, 400, "Expected a single JSON object")
		return false
	}
	return true
}
func (s *Server) Identity(r *http.Request) (auth.Identity, error) {
	cookie, e := r.Cookie("panasms_session")
	if e != nil {
		return auth.Identity{}, e
	}
	username, e := s.Store.User(cookie.Value)
	if e != nil {
		return auth.Identity{}, e
	}
	id, err := auth.Lookup(username, s.Allowed)
	if err != nil {
		return auth.Identity{}, err
	}
	if !s.Store.SessionMatches(cookie.Value, id.UID, id.Epoch) {
		return auth.Identity{}, fmt.Errorf("session revoked")
	}
	req, err := http.NewRequestWithContext(r.Context(), "GET", "http://agent/account-check?user="+url.QueryEscape(username), nil)
	if err != nil {
		return auth.Identity{}, err
	}
	response, err := s.Agent.Do(req)
	if err != nil {
		return auth.Identity{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return auth.Identity{}, fmt.Errorf("account unavailable")
	}
	return id, nil
}
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'"+healthConnectSource(r.Host)+"; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
			if strings.HasPrefix(r.URL.Path, "/api/") {
				w.Header().Set("Cache-Control", "no-store")
			}
			if r.Method != "GET" && r.Method != "HEAD" {
				scheme := "http"
				if s.Secure {
					scheme = "https"
				}
				if r.Header.Get("Origin") != scheme+"://"+r.Host || r.Header.Get("X-PaNasMs-Request") != "1" {
					fail(w, 403, "Invalid request origin")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	r.Get("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		allowHealthProbe(w, r)
		jsonResponse(w, 200, map[string]string{"status": "ok", "version": "0.2.6", "product": "PaNasMs"})
	})
	r.Post("/api/v1/login", s.login)
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id, e := s.Identity(r)
				if e != nil {
					fail(w, 401, "Sign-in required")
					return
				}
				if !userRoute(id, r) {
					fail(w, 403, "Administrator permissions required")
					return
				}
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
			})
		})
		r.Get("/api/v1/session", func(w http.ResponseWriter, r *http.Request) { jsonResponse(w, 200, r.Context().Value(identityKey{})) })
		r.Post("/api/v1/logout", func(w http.ResponseWriter, r *http.Request) {
			c, _ := r.Cookie("panasms_session")
			if e := s.Store.Revoke(c.Value); e != nil {
				fail(w, 500, "Could not end session")
				return
			}
			s.cookie(w, "", -1)
			w.WriteHeader(204)
		})
		r.Get("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
			values := r.URL.Query()
			values.Set("view", "accounts")
			r.URL.RawQuery = values.Encode()
			s.manage(w, r)
		})
		r.Get("/api/v1/sessions", s.sessions)
		r.Post("/api/v1/sessions", s.sessions)
		r.Get("/api/v1/security-history", s.securityHistory)
		r.Get("/api/v1/storage", func(w http.ResponseWriter, r *http.Request) {
			v, e := system.StorageRead(r.Context())
			if e != nil {
				fail(w, 503, "Could not read storage")
				return
			}
			jsonResponse(w, 200, v)
		})
		r.Get("/api/v1/notifications", func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value(identityKey{}).(auth.Identity).Role != "admin" {
				jsonResponse(w, 200, []any{})
				return
			}
			v, e := s.notifications(r.Context(), r.Context().Value(identityKey{}).(auth.Identity).Username)
			if e != nil {
				fail(w, 503, "Notifications unavailable")
				return
			}
			jsonResponse(w, 200, v)
		})
		r.Delete("/api/v1/notifications", func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value(identityKey{}).(auth.Identity).Role != "admin" {
				fail(w, 403, "Administrator permissions required")
				return
			}
			alerts, e := s.notifications(r.Context(), r.Context().Value(identityKey{}).(auth.Identity).Username)
			if e != nil {
				fail(w, 503, "Could not read notifications")
				return
			}
			if e := s.Store.DismissResolvedAlerts(r.Context().Value(identityKey{}).(auth.Identity).Username, alerts); e != nil {
				fail(w, 503, "Could not clear notification history")
				return
			}
			w.WriteHeader(204)
		})
		r.Get("/api/v1/metrics/history", func(w http.ResponseWriter, r *http.Request) {
			hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
			if hours < 1 || hours > 168 {
				hours = 24
			}
			v, e := s.Store.MetricsHistory(hours)
			if e != nil {
				fail(w, 503, "History unavailable")
				return
			}
			jsonResponse(w, 200, v)
		})
		r.Get("/api/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
			s.metricsMu.RLock()
			defer s.metricsMu.RUnlock()
			if s.metricsError {
				fail(w, 503, "Metrics unavailable")
				return
			}
			jsonResponse(w, 200, s.metrics)
		})
		r.Get("/api/v1/wallpaper", s.wallpaper)
		r.Put("/api/v1/wallpaper", s.wallpaper)
		r.Delete("/api/v1/wallpaper", s.wallpaper)
		r.Get("/api/v1/wallpaper/image", s.wallpaperImage)
		r.Get("/api/v1/preferences", func(w http.ResponseWriter, r *http.Request) {
			id := r.Context().Value(identityKey{}).(auth.Identity)
			p, e := s.Store.Preferences(id.Username)
			if e != nil {
				fail(w, 500, "Could not read settings")
				return
			}
			jsonResponse(w, 200, p)
		})
		r.Put("/api/v1/preferences", func(w http.ResponseWriter, r *http.Request) {
			var p store.Preferences
			if !decodeLimit(w, r, &p, 1<<20) {
				return
			}
			id := r.Context().Value(identityKey{}).(auth.Identity)
			if p.Language == "" {
				current, err := s.Store.Preferences(id.Username)
				if err != nil {
					fail(w, 500, "Could not read language preference")
					return
				}
				p.Language = current.Language
			}
			if p.Language != "en" && p.Language != "ru" && p.Language != "uk" {
				fail(w, 400, "Unsupported interface language")
				return
			}
			if e := system.ValidatePreferences(p.Theme, p.Layouts); e != nil {
				fail(w, 400, "Invalid settings")
				return
			}
			if !validTaskbar(p.Taskbar) || !validDesktop(p.DesktopLayouts) {
				fail(w, 400, "Invalid layout")
				return
			}
			if len(p.SmartCrcBaselines) > 256 {
				fail(w, 400, "Too many disks")
				return
			}
			for key, value := range p.SmartCrcBaselines {
				if len(key) == 0 || len(key) > 512 || value > 9007199254740991 {
					fail(w, 400, "Invalid CRC count")
					return
				}
			}
			if s.Store.Save(id.Username, p) != nil {
				fail(w, 500, "Could not save settings")
				return
			}
			jsonResponse(w, 200, p)
		})
		r.Get("/api/v1/events", s.events)
		r.Get("/api/v1/module-assets/*", s.moduleAssets)
		r.Post("/api/v1/modules/upload", s.moduleUpload)
		r.HandleFunc("/api/v1/module-api/*", s.moduleAPI)
		r.Get("/api/v1/files/content", s.files)
		r.Put("/api/v1/files/content", s.files)
		r.Get("/api/v1/terminal", s.terminal)
		r.Get("/api/v1/manage", s.manage)
		r.Post("/api/v1/manage", s.manage)
		r.Get("/api/v1/avatar", s.avatar)
		r.Get("/api/v1/avatar/image", s.avatar)
		r.Put("/api/v1/avatar", s.avatar)
		r.Delete("/api/v1/avatar", s.avatar)
		r.Get("/api/v1/profile", s.profile)
		r.Post("/api/v1/profile", s.profile)
		r.Get("/api/v1/cooling", s.cooling)
		r.Put("/api/v1/cooling", s.cooling)
	})
	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			fail(w, 404, "API method not found")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(405)
			return
		}
		name := filepath.Join(s.Static, filepath.Clean("/"+r.URL.Path))
		info, e := os.Stat(name)
		if e != nil || info.IsDir() {
			http.ServeFile(w, r, filepath.Join(s.Static, "index.html"))
			return
		}
		http.ServeFile(w, r, name)
	}))
	return r
}

type identityKey struct{}

func (s *Server) cookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: "panasms_session", Value: value, Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}
func (s *Server) permit(address string) bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	now := time.Now()
	cut := now.Add(-time.Minute)
	for k, attempts := range s.attempts {
		kept := attempts[:0]
		for _, t := range attempts {
			if t.After(cut) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(s.attempts, k)
		} else {
			s.attempts[k] = kept
		}
	}
	if len(s.attempts) >= 1024 || len(s.attempts[address]) >= 5 {
		return false
	}
	s.attempts[address] = append(s.attempts[address], now)
	return true
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	addr, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !s.permit(addr) {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "Too many attempts. Wait a minute.")
		return
	}
	var body struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		NewPassword string `json:"newPassword"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(body.NewPassword) > 4096 || strings.ContainsAny(body.NewPassword, "\x00\r\n") || len(body.Username) > 64 || len(body.Password) > 4096 || body.Password == "" || strings.ContainsRune(body.Password, 0) || strings.ContainsRune(body.Username, 0) {
		fail(w, 400, "Check your username and password")
		return
	}
	b, _ := json.Marshal(body)
	req, e := http.NewRequestWithContext(r.Context(), "POST", "http://agent/authenticate", bytes.NewReader(b))
	if e != nil {
		fail(w, 500, "Sign-in error")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := s.Agent.Do(req)
	if e != nil {
		fail(w, 503, "System sign-in service unavailable")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		if resp.StatusCode == 409 || resp.StatusCode == 400 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, io.LimitReader(resp.Body, 8192))
			return
		}
		s.Store.Audit(body.Username, body.Username, "login", "failed")
		fail(w, 401, "Incorrect password or access not allowed")
		return
	}
	var id auth.Identity
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&id) != nil || id.Username != body.Username {
		fail(w, 503, "Sign-in service error")
		return
	}
	if err := s.Store.BindAccount(id.Username, id.UID, id.Principal); err != nil {
		fail(w, 503, "Account storage unavailable")
		return
	}
	if body.NewPassword != "" {
		s.Store.RevokeUser(id.Username)
	}
	token, e := s.Store.Session(id.Username)
	if e != nil {
		fail(w, 500, "Could not create session")
		return
	}
	address, _, _ := net.SplitHostPort(r.RemoteAddr)
	if s.Store.SessionDetails(token, id.UID, id.Epoch, address, r.UserAgent()) != nil {
		s.Store.Revoke(token)
		fail(w, 500, "Could not create session")
		return
	}
	s.Store.Audit(id.Username, id.Username, "login", "succeeded")
	s.Store.Alert("smb-password:"+id.Username, "SMB password synchronization failed for "+id.Username+". Sign in again to retry or ask an administrator to check Users / Security.", id.SMBSyncWarning)
	s.cookie(w, token, 28800)
	jsonResponse(w, 200, id)
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	c, e := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(1024)
	ctx := c.CloseRead(r.Context())
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	last := s.revision.Load()
	var lastJobs any
	lastNotifications := s.notificationsRevision.Load()
	lastMetrics := time.Time{}
	lastAuth := time.Now()
	send := func(kind string, value any) error {
		b, _ := json.Marshal(map[string]any{"version": 1, "type": kind, "data": value})
		cx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return c.Write(cx, websocket.MessageText, b)
	}
	if send("resync", nil) != nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if coolingState, err := cooling.Read(); err == nil {
				if send("cooling", coolingState) != nil {
					return
				}
			} else {
				if send("cooling.unavailable", nil) != nil {
					return
				}
			}
			if time.Since(lastAuth) >= 5*time.Second {
				if _, e = s.Identity(r); e != nil {
					c.Close(websocket.StatusPolicyViolation, "session expired")
					return
				}
				lastAuth = time.Now()
			}
			if revision := s.jobsRevision.Load(); revision != lastJobs {
				lastJobs = revision
				if send("jobs.changed", nil) != nil {
					return
				}
			}
			if revision := s.notificationsRevision.Load(); revision != lastNotifications {
				lastNotifications = revision
				if send("notifications.changed", nil) != nil {
					return
				}
			}
			rev := s.revision.Load()
			if rev != last {
				last = rev
				if send("storage.changed", nil) != nil {
					return
				}
			}
			s.metricsMu.RLock()
			m := s.metrics
			bad := s.metricsError
			s.metricsMu.RUnlock()
			if bad {
				if send("metrics.unavailable", nil) != nil {
					return
				}
			} else if m.ObservedAt != lastMetrics {
				lastMetrics = m.ObservedAt
				if send("metrics", m) != nil {
					return
				}
			}
		}
	}
}

func (s *Server) cooling(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	req, err := http.NewRequestWithContext(r.Context(), r.Method, "http://agent/cooling?user="+url.QueryEscape(id.Username), r.Body)
	if err != nil {
		fail(w, 500, "Cooling request error")
		return
	}
	response, err := s.Agent.Do(req)
	if err != nil {
		fail(w, 503, "Cooling controller unavailable")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		fail(w, response.StatusCode, "Could not read or apply cooling settings")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, io.LimitReader(response.Body, 65536))
}

func (s *Server) profile(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	var body map[string]string
	var reader io.Reader
	if r.Method == "POST" {
		if !s.permit("profile:" + id.Username) {
			fail(w, 429, "Too many attempts. Wait a minute.")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 24000)
		d := json.NewDecoder(r.Body)
		if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF {
			fail(w, 400, "Invalid request")
			return
		}
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, "http://agent/profile?user="+url.QueryEscape(id.Username), reader)
	if err != nil {
		fail(w, 500, "Profile error")
		return
	}
	resp, err := s.Agent.Do(req)
	if err != nil {
		fail(w, 503, "Profile service unavailable")
		return
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-PaNasMs-Password-Changed") == "1" {
		s.Store.RevokeUser(id.Username)
		s.cookie(w, "", -1)
	}
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		message := "Could not update profile. Check your input."
		if resp.StatusCode == 403 {
			message = "Incorrect current password"
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == 400 && len(raw) > 0 {
			message = strings.TrimSpace(string(raw))
		}
		fail(w, resp.StatusCode, message)
		return
	}
	if r.Method == "POST" {
		s.Store.Audit(id.Username, id.Username, "profile."+body["action"], "succeeded")
	}
	if body["action"] == "password" {
		if s.Store.RevokeUser(id.Username) != nil {
			fail(w, 500, "Password changed, but panel sessions could not be ended")
			return
		}
		s.cookie(w, "", -1)
	}
	if resp.StatusCode == 204 {
		w.WriteHeader(204)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, io.LimitReader(resp.Body, 131072))
}

func (s *Server) manage(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	values := r.URL.Query()
	values.Set("user", id.Username)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	req, err := http.NewRequestWithContext(r.Context(), r.Method, "http://agent/manage?"+values.Encode(), r.Body)
	if err != nil {
		fail(w, 400, "Invalid request")
		return
	}
	client := *s.Agent
	client.Timeout = 40 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		fail(w, 503, "Management service unavailable")
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, 4<<20))
}

// tileSize даёт размер плитки в ячейках. Виджеты с постоянным составом
// перечислены поимённо; у виджетов, которых столько же, сколько устройств,
// проверяется семейство и ключ, а не полное имя.
func tileSize(kind string) ([2]int, bool) {
	sizes := map[string][2]int{"clock": {2, 1}, "cpu": {2, 2}, "hddCooling": {2, 2}, "memory": {2, 2}, "cooling": {2, 2}, "system": {2, 2}, "network": {2, 2}, "systemDisk": {2, 2}, "disks": {2, 2}, "users": {1, 1}, "storage": {1, 1}, "files": {1, 1}, "app-settings": {1, 1}, "app-terminal": {1, 1}, "app-system": {1, 1}, "app-sharing": {1, 1}, "app-history": {1, 1}, "app-modules": {1, 1}, "app-network": {1, 1}}
	if size, ok := sizes[kind]; ok {
		return size, true
	}
	if key, ok := strings.CutPrefix(kind, "disk-temp:"); ok && validWidgetKey(key) {
		return [2]int{2, 1}, true
	}
	for id, m := range modules.Known() {
		if kind == "app-"+id {
			return [2]int{1, 1}, true
		}
		if size, ok := m.Widgets[kind]; ok {
			return size, true
		}
	}
	return [2]int{}, false
}

// Ключ виджета устройства приходит от клиента, поэтому набор символов сужен до
// того, что встречается в серийных номерах и именах блочных устройств.
func validWidgetKey(key string) bool {
	if len(key) == 0 || len(key) > 64 {
		return false
	}
	for _, r := range key {
		letter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		digit := r >= '0' && r <= '9'
		if !letter && !digit && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func validDesktop(layouts map[string][]store.DesktopTile) bool {
	for mode, tiles := range layouts {
		cols := map[string]int{"wide": 8, "medium": 6, "mobile": 2}[mode]
		if cols == 0 || len(tiles) > 100 {
			return false
		}
		seen := map[string]bool{}
		cells := map[[2]int]bool{}
		for _, t := range tiles {
			size, ok := tileSize(t.Kind)
			if !ok || t.ID == "" || len(t.ID) > 100 || seen[t.ID] || t.X < 0 || t.Y < 0 || t.X+size[0] > cols || t.Y+size[1] > 100 {
				return false
			}
			seen[t.ID] = true
			for x := t.X; x < t.X+size[0]; x++ {
				for y := t.Y; y < t.Y+size[1]; y++ {
					k := [2]int{x, y}
					if cells[k] {
						return false
					}
					cells[k] = true
				}
			}
		}
	}
	return true
}

func validTaskbar(ids *[]string) bool {
	if ids == nil {
		return true
	}
	allowed := map[string]bool{"modules": true, "users": true, "storage": true, "settings": true, "terminal": true, "files": true, "sharing": true, "system": true, "history": true, "network": true}
	for id := range modules.Known() {
		allowed[id] = true
	}
	seen := map[string]bool{}
	for _, id := range *ids {
		if !allowed[id] || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
