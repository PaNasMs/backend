package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/external"
	"panasms.local/backend/internal/store"
	"strings"
	"sync"
	"time"
)

type externalFlow struct {
	State, Nonce, Verifier, Revision, Purpose, Session string
	Connection                                         store.ExternalConnection
	Consumer, Capability, Scope, Installation          string
	Identity                                           auth.Identity
	Expires, NextPoll                                  time.Time
	Busy                                               bool
}
type externalFlows struct {
	sync.Mutex
	pending       map[string]*externalFlow
	client        *http.Client
	exchangeGrant func(context.Context, *http.Client, string, string, string, string, string, string) (external.Authorization, error)
	exchange      func(context.Context, *http.Client, string, string, string, string, string) (external.Account, error)
}

func newExternalFlows() *externalFlows {
	return &externalFlows{pending: map[string]*externalFlow{}, client: &http.Client{Timeout: 15 * time.Second}, exchange: external.Exchange, exchangeGrant: external.ExchangeGrant}
}
func randomExternal() string { return hex.EncodeToString(randomExternalBytes()) }
func randomExternalBytes() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func externalDigest(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}
func (s *Server) externalCookie(w http.ResponseWriter, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: "panasms_external_flow", Value: value, Path: "/api/v1/external", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: age})
}
func (s *Server) externalProviders(w http.ResponseWriter, r *http.Request) {
	c, err := s.Store.ExternalConfig("google")
	if err != nil {
		fail(w, 503, "external.unavailable")
		return
	}
	jsonResponse(w, 200, map[string]any{"google": map[string]bool{"enabled": c.Enabled && c.ClientID != "" && c.ClientSecret != ""}})
}
func (s *Server) externalSettings(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	if id.Role != "admin" {
		fail(w, 403, "Administrator permissions required")
		return
	}
	s.external.Lock()
	defer s.external.Unlock()
	current, err := s.Store.ExternalConfig("google")
	if err != nil {
		fail(w, 503, "external.unavailable")
		return
	}
	if r.Method == "PUT" {
		var body struct {
			ClientID     string `json:"clientId"`
			ClientSecret string `json:"clientSecret"`
			Enabled      bool   `json:"enabled"`
		}
		if !decode(w, r, &body) {
			return
		}
		body.ClientID = strings.TrimSpace(body.ClientID)
		body.ClientSecret = strings.TrimSpace(body.ClientSecret)
		if len(body.ClientID) > 256 || len(body.ClientSecret) > 4096 || strings.ContainsAny(body.ClientID+body.ClientSecret, "\r\n\x00") || !strings.HasSuffix(body.ClientID, ".apps.googleusercontent.com") {
			fail(w, 400, "external.invalidClient")
			return
		}
		if body.ClientSecret == "" && body.ClientID == current.ClientID {
			body.ClientSecret = current.ClientSecret
		}
		if body.ClientSecret == "" {
			fail(w, 400, "external.secretRequired")
			return
		}
		current = store.ExternalConfig{ClientID: body.ClientID, ClientSecret: body.ClientSecret, Enabled: body.Enabled, Revision: randomExternal()}
		if err = s.Store.SaveExternalConfig("google", current); err != nil {
			fail(w, 503, "external.unavailable")
			return
		}
		clear(s.external.pending)
		s.Store.Audit(id.Username, id.Username, "external.settings", "succeeded")
	}
	jsonResponse(w, 200, map[string]any{"provider": "google", "clientId": current.ClientID, "secretConfigured": current.ClientSecret != "", "enabled": current.Enabled, "redirectUri": external.RedirectURI})
}
func (s *Server) externalReauthenticate(r *http.Request, id auth.Identity, password string) bool {
	if len(password) == 0 || len(password) > 4096 || strings.ContainsAny(password, "\x00\r\n") || !s.permit("external-proof:"+id.Username) {
		return false
	}
	raw, _ := json.Marshal(map[string]string{"username": id.Username, "password": password})
	req, err := http.NewRequestWithContext(r.Context(), "POST", "http://agent/authenticate", bytes.NewReader(raw))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := s.Agent.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	var checked auth.Identity
	return res.StatusCode == 200 && json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&checked) == nil && checked.Username == id.Username && checked.UID == id.UID && checked.Principal == id.Principal && checked.Epoch == id.Epoch
}
func (s *Server) externalConnections(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
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
		if err := s.Store.UnlinkExternal(id.Username, body.ID); err != nil {
			fail(w, 409, "external.unlinkFailed")
			return
		}
		for key, f := range s.external.pending {
			if f.Identity.Username == id.Username {
				delete(s.external.pending, key)
			}
		}
		s.Store.Audit(id.Username, id.Username, "external.unlink", "succeeded")
		s.cookie(w, "", -1)
		w.WriteHeader(204)
		return
	}
	result, err := s.Store.ExternalConnections(id.Username, id.UID, id.Principal)
	if err != nil {
		fail(w, 503, "external.unavailable")
		return
	}
	jsonResponse(w, 200, result)
}
func (s *Server) externalStart(w http.ResponseWriter, r *http.Request) {
	address, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !s.permit("external-start:" + address) {
		fail(w, 429, "external.tooMany")
		return
	}
	var body struct {
		Purpose      string `json:"purpose"`
		ConnectionID string `json:"connectionId"`
		Consumer     string `json:"consumer"`
		Capability   string `json:"capability"`
		Password     string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	flow := &externalFlow{Purpose: body.Purpose, State: randomExternal(), Nonce: randomExternal(), Verifier: randomExternal(), Expires: time.Now().Add(10 * time.Minute)}
	if body.Purpose == "link" || body.Purpose == "grant" {
		id, err := s.Identity(r)
		if err != nil {
			fail(w, 401, "Sign-in required")
			return
		}
		if !s.externalReauthenticate(r, id, body.Password) {
			fail(w, 403, "external.passwordRequired")
			return
		}
		if body.Purpose == "grant" {
			c, err := s.Store.ExternalConnection(body.ConnectionID)
			policy, installation, ok := grantInstallation(body.Consumer, body.Capability)
			if err != nil || !s.grantOwnerMatches(c, id) || !ok || c.Provider != policy.Provider {
				fail(w, 403, "external.grantUnavailable")
				return
			}
			flow.Connection = c
			flow.Consumer = body.Consumer
			flow.Capability = body.Capability
			flow.Scope = policy.Scope
			flow.Installation = installation
		}
		flow.Identity = id
		c, _ := r.Cookie("panasms_session")
		flow.Session = externalDigest(c.Value)
	} else if body.Purpose != "login" {
		fail(w, 400, "Invalid request")
		return
	}
	s.external.Lock()
	defer s.external.Unlock()
	config, err := s.Store.ExternalConfig("google")
	if err != nil {
		fail(w, 503, "external.unavailable")
		return
	}
	if !config.Enabled || config.ClientID == "" || config.ClientSecret == "" {
		fail(w, 409, "external.notConfigured")
		return
	}
	for key, f := range s.external.pending {
		if time.Now().After(f.Expires) {
			delete(s.external.pending, key)
		}
	}
	if len(s.external.pending) >= 256 {
		fail(w, 429, "external.tooMany")
		return
	}
	if old, err := r.Cookie("panasms_external_flow"); err == nil {
		delete(s.external.pending, externalDigest(old.Value))
	}
	ticket := randomExternal()
	flow.Revision = config.Revision
	s.external.pending[externalDigest(ticket)] = flow
	s.externalCookie(w, ticket, 600)
	authorize := external.Authorize(config.ClientID, flow.State, flow.Nonce, flow.Verifier)
	if flow.Purpose == "grant" {
		authorize = external.AuthorizeGrant(config.ClientID, flow.State, flow.Nonce, flow.Verifier, flow.Connection.Subject, flow.Scope)
	}
	jsonResponse(w, 200, map[string]any{"url": authorize, "expiresIn": 600})
}
func (s *Server) externalCancel(w http.ResponseWriter, r *http.Request) {
	s.external.Lock()
	defer s.external.Unlock()
	if c, err := r.Cookie("panasms_external_flow"); err == nil {
		delete(s.external.pending, externalDigest(c.Value))
	}
	s.externalCookie(w, "", -1)
	w.WriteHeader(204)
}
func (s *Server) checkedExternalOwner(ctx context.Context, c store.ExternalConnection) (auth.Identity, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://agent/account-check?user="+url.QueryEscape(c.Username), nil)
	if err != nil {
		return auth.Identity{}, err
	}
	res, err := s.Agent.Do(req)
	if err != nil {
		return auth.Identity{}, err
	}
	defer res.Body.Close()
	var id auth.Identity
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&id) != nil || id.Username != c.Username || id.UID != c.UID || id.Principal != c.Principal {
		return id, errors.New("account unavailable")
	}
	return id, nil
}
func (s *Server) externalPoll(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("panasms_external_flow")
	if err != nil {
		fail(w, 410, "external.expired")
		return
	}
	key := externalDigest(cookie.Value)
	s.external.Lock()
	flow := s.external.pending[key]
	if flow == nil || time.Now().After(flow.Expires) {
		delete(s.external.pending, key)
		s.external.Unlock()
		fail(w, 410, "external.expired")
		return
	}
	if flow.Busy || time.Now().Before(flow.NextPoll) {
		s.external.Unlock()
		jsonResponse(w, 202, map[string]string{"status": "pending"})
		return
	}
	flow.Busy = true
	flow.NextPoll = time.Now().Add(3 * time.Second)
	s.external.Unlock()
	defer func() { s.external.Lock(); flow.Busy = false; s.external.Unlock() }()
	if flow.Purpose == "link" || flow.Purpose == "grant" {
		id, e := s.Identity(r)
		session, se := r.Cookie("panasms_session")
		if e != nil || se != nil || externalDigest(session.Value) != flow.Session || id.Username != flow.Identity.Username || id.UID != flow.Identity.UID || id.Principal != flow.Identity.Principal || id.Epoch != flow.Identity.Epoch {
			s.externalCancelPending(r)
			fail(w, 401, "Sign-in required")
			return
		}
	}
	req, _ := http.NewRequestWithContext(r.Context(), "GET", external.Gateway+"/exchange?state="+url.QueryEscape(flow.State), nil)
	res, err := s.external.client.Do(req)
	if err != nil {
		fail(w, 503, "external.gatewayUnavailable")
		return
	}
	defer res.Body.Close()
	if res.StatusCode == 404 {
		jsonResponse(w, 202, map[string]string{"status": "pending"})
		return
	}
	var result struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 8192)).Decode(&result) != nil {
		fail(w, 503, "external.gatewayUnavailable")
		return
	}
	s.external.Lock()
	config, e := s.Store.ExternalConfig("google")
	active := s.external.pending[key] == flow && time.Now().Before(flow.Expires) && e == nil && config.Enabled && config.Revision == flow.Revision
	s.external.Unlock()
	defer s.externalCancelPending(r)
	s.externalCookie(w, "", -1)
	if !active {
		fail(w, 410, "external.expired")
		return
	}
	if result.Error != "" || result.Code == "" {
		fail(w, 400, "external.denied")
		return
	}
	var account external.Account
	var authorization external.Authorization
	if flow.Purpose == "grant" {
		authorization, err = s.external.exchangeGrant(r.Context(), s.external.client, config.ClientID, config.ClientSecret, result.Code, flow.Nonce, flow.Verifier, flow.Scope)
		account = authorization.Account
	} else {
		account, err = s.external.exchange(r.Context(), s.external.client, config.ClientID, config.ClientSecret, result.Code, flow.Nonce, flow.Verifier)
	}
	if err != nil {
		fail(w, 401, "external.validationFailed")
		return
	}
	s.external.Lock()
	defer s.external.Unlock()
	current, err := s.Store.ExternalConfig("google")
	if err != nil || s.external.pending[key] != flow || time.Now().After(flow.Expires) || !current.Enabled || current.Revision != flow.Revision {
		fail(w, 410, "external.expired")
		return
	}
	if flow.Purpose == "link" || flow.Purpose == "grant" {
		id, err := s.Identity(r)
		if err != nil || id.Username != flow.Identity.Username || id.UID != flow.Identity.UID || id.Principal != flow.Identity.Principal || id.Epoch != flow.Identity.Epoch {
			fail(w, 401, "Sign-in required")
			return
		}
		if flow.Purpose == "grant" {
			owner, e := s.Store.ExternalConnection(flow.Connection.ID)
			policy, installation, ok := grantInstallation(flow.Consumer, flow.Capability)
			if e != nil || !s.grantOwnerMatches(owner, id) || owner.Subject != account.Subject || !ok || installation != flow.Installation || policy.Scope != flow.Scope {
				fail(w, 403, "external.grantUnavailable")
				return
			}
			grant := store.ExternalGrant{ID: randomExternal(), ConnectionID: owner.ID, Consumer: flow.Consumer, Capability: flow.Capability, Scope: flow.Scope, Revision: flow.Revision, Epoch: id.Epoch, Installation: installation, Token: authorization.Token}
			if s.Store.SaveExternalGrant(grant) != nil {
				fail(w, 503, "external.unavailable")
				return
			}
			s.Store.Audit(id.Username, id.Username, "external.grant", "succeeded")
			jsonResponse(w, 200, map[string]string{"status": "granted", "grantId": grant.ID})
			return
		}
		if err = s.Store.LinkExternal(store.ExternalConnection{ID: randomExternal(), Provider: "google", Subject: account.Subject, Username: id.Username, UID: id.UID, Principal: id.Principal, Email: account.Email, Name: account.Name}); err != nil {
			fail(w, 409, "external.alreadyLinked")
			return
		}
		s.Store.Audit(id.Username, id.Username, "external.link", "succeeded")
		jsonResponse(w, 200, map[string]string{"status": "linked"})
		return
	}
	owner, err := s.Store.ExternalOwner("google", account.Subject)
	if err != nil {
		fail(w, 403, "external.notLinked")
		return
	}
	id, err := s.checkedExternalOwner(r.Context(), owner)
	if err != nil {
		s.Store.Audit(owner.Username, owner.Username, "login.google", "denied")
		fail(w, 403, "external.accountUnavailable")
		return
	}
	if err = s.Store.BindAccount(id.Username, id.UID, id.Principal); err != nil {
		fail(w, 503, "external.unavailable")
		return
	}
	token, err := s.Store.Session(id.Username)
	if err != nil {
		fail(w, 503, "external.unavailable")
		return
	}
	address, _, _ := net.SplitHostPort(r.RemoteAddr)
	if err = s.Store.SessionDetails(token, id.UID, id.Epoch, address, r.UserAgent()); err != nil {
		s.Store.Revoke(token)
		fail(w, 503, "external.unavailable")
		return
	}
	s.Store.Audit(id.Username, id.Username, "login.google", "succeeded")
	s.cookie(w, token, 28800)
	jsonResponse(w, 200, map[string]string{"status": "authenticated"})
}

func (s *Server) externalCancelPending(r *http.Request) {
	s.external.Lock()
	defer s.external.Unlock()
	if c, err := r.Cookie("panasms_external_flow"); err == nil {
		delete(s.external.pending, externalDigest(c.Value))
	}
}
