package api

import (
	"net/http"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/store"
)

func (s *Server) externalGrants(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == "DELETE" {
		var body struct {
			ID       string `json:"id"`
			Password string `json:"password"`
		}
		if !decode(w, r, &body) {
			return
		}
		if !s.externalReauthenticate(r, id, body.Password) {
			fail(w, 403, "external.passwordRequired")
			return
		}
		s.external.Lock()
		defer s.external.Unlock()
		grants, err := s.Store.ExternalGrants(id.Username, id.UID, id.Principal)
		if err != nil {
			fail(w, 503, "external.unavailable")
			return
		}
		for _, g := range grants {
			if g.ID == body.ID {
				if s.Store.DeleteExternalGrant(g.ID) != nil {
					fail(w, 503, "external.unavailable")
					return
				}
				for key, f := range s.external.pending {
					if f.Connection.ID == g.ConnectionID && f.Consumer == g.Consumer && f.Capability == g.Capability {
						delete(s.external.pending, key)
					}
				}
				s.Store.Audit(id.Username, id.Username, "external.grant.revoke", "succeeded")
				w.WriteHeader(204)
				return
			}
		}
		fail(w, 404, "external.grantUnavailable")
		return
	}
	grants, err := s.Store.ExternalGrants(id.Username, id.UID, id.Principal)
	if err != nil {
		fail(w, 503, "external.unavailable")
		return
	}
	config, err := s.Store.ExternalConfig("google")
	if err != nil {
		fail(w, 503, "external.unavailable")
		return
	}
	for i, g := range grants {
		_, installation, ok := grantInstallation(g.Consumer, g.Capability)
		if g.Status == "active" {
			if !ok || !config.Enabled {
				grants[i].Status = "unavailable"
			} else if g.Revision != config.Revision || g.Epoch != id.Epoch || g.Installation != installation {
				grants[i].Status = "reconnect_required"
			}
		}
	}
	jsonResponse(w, 200, grants)
}

func (s *Server) grantOwnerMatches(c store.ExternalConnection, id auth.Identity) bool {
	return c.Username == id.Username && c.UID == id.UID && c.Principal == id.Principal
}
