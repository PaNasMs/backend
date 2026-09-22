package api

import (
	"net/http"
	"panasms.local/backend/internal/auth"
	"strings"
)

func userRoute(id auth.Identity, r *http.Request) bool {
	if id.Role == "admin" {
		return true
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	switch path {
	case "external/connections", "session", "logout", "preferences", "wallpaper", "wallpaper/image", "avatar", "avatar/image", "profile", "sessions", "security-history", "files/content":
		return true
	case "events", "metrics", "metrics/history", "storage", "cooling", "notifications":
		return r.Method == "GET"
	case "manage":
		if r.Method == "POST" {
			return true
		}
		switch r.URL.Query().Get("view") {
		case "jobs", "files", "modules", "account-details", "account-sessions", "storage-options":
			return true
		}
		return false
	}
	return r.Method == "GET" && strings.HasPrefix(path, "module-assets/files/")
}
func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(identityKey{}).(auth.Identity)
	user := r.URL.Query().Get("user")
	if user == "" {
		user = actor.Username
	}
	if actor.Role != "admin" && user != actor.Username {
		fail(w, 403, "Access denied")
		return
	}
	if r.Method == "POST" {
		var body struct {
			ID string `json:"id"`
		}
		if !decode(w, r, &body) {
			return
		}
		if err := s.Store.EndSession(user, body.ID); err != nil {
			fail(w, 409, err.Error())
			return
		}
		s.Store.Audit(user, actor.Username, "session.end", "succeeded")
		w.WriteHeader(204)
		return
	}
	if target, err := auth.Lookup(user, s.Allowed); err != nil {
		s.Store.RevokeUser(user)
	} else {
		s.Store.PruneSessions(user, target.UID, target.Epoch)
	}
	cookie, _ := r.Cookie("panasms_session")
	result, err := s.Store.Sessions(user, cookie.Value)
	if err != nil {
		fail(w, 503, "Sessions unavailable")
		return
	}
	jsonResponse(w, 200, result)
}
func (s *Server) securityHistory(w http.ResponseWriter, r *http.Request) {
	actor := r.Context().Value(identityKey{}).(auth.Identity)
	user := r.URL.Query().Get("user")
	if user == "" {
		user = actor.Username
	}
	if actor.Role != "admin" && user != actor.Username {
		fail(w, 403, "Access denied")
		return
	}
	result, err := s.Store.History(user)
	if err != nil {
		fail(w, 503, "History unavailable")
		return
	}
	jsonResponse(w, 200, result)
}
