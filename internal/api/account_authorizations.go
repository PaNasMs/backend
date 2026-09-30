package api

import (
	"database/sql"
	"errors"
	"panasms.local/backend/internal/store"
)

func (s *Server) reuseAccountAuthorization(flow *externalFlow, config store.ExternalConfig) (string, error) {
	id := flow.Identity
	existing, err := s.Store.ExternalGrants(id.Username, id.UID, id.Principal)
	if err != nil {
		return "", err
	}
	authorization, err := s.Store.AccountAuthorization(flow.Connection.ID, flow.Scope)
	if errors.Is(err, sql.ErrNoRows) {
		// Preserve existing consents when upgrading from per-module OAuth storage.
		for _, g := range existing {
			if g.ConnectionID != flow.Connection.ID || g.Scope != flow.Scope || g.Status != "active" || g.Revision != config.Revision || g.Epoch != id.Epoch {
				continue
			}
			legacy, e := s.Store.ExternalGrant(g.ID)
			if e != nil {
				return "", e
			}
			if legacy.Token == nil {
				continue
			}
			if e = s.Store.SaveAccountAuthorization(legacy); e != nil {
				return "", e
			}
			authorization, err = s.Store.AccountAuthorization(flow.Connection.ID, flow.Scope)
			break
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if authorization.Status != "active" || authorization.Revision != config.Revision || authorization.Epoch != id.Epoch || authorization.Token == nil {
		return "", nil
	}
	grantID := randomExternal()
	for _, g := range existing {
		if g.ConnectionID == flow.Connection.ID && g.Consumer == flow.Consumer && g.Capability == flow.Capability {
			grantID = g.ID
			break
		}
	}
	g := store.ExternalGrant{ID: grantID, ConnectionID: flow.Connection.ID, Consumer: flow.Consumer, Capability: flow.Capability, Scope: flow.Scope, Revision: config.Revision, Epoch: id.Epoch, Installation: flow.Installation, Token: nil}
	if err = s.Store.SaveExternalGrant(g); err != nil {
		return "", err
	}
	s.Store.Audit(id.Username, id.Username, "external.grant", "succeeded")
	return grantID, nil
}
