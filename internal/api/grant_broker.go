package api

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"net/http"
	"os"
	"panasms.local/backend/internal/external"
	"path/filepath"
	"strings"
	"time"
)

type grantPeer struct {
	PID int32
	UID uint32
}
type grantPeerKey struct{}

func peerConsumer(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[0] != "0" || fields[1] != "" {
			continue
		}
		parts := strings.Split(strings.Trim(fields[2], "/"), "/")
		if len(parts) < 2 || parts[0] != "system.slice" {
			continue
		}
		unit := parts[1]
		if strings.HasPrefix(unit, "panasms-module-") && strings.HasSuffix(unit, ".service") {
			consumer := strings.TrimSuffix(strings.TrimPrefix(unit, "panasms-module-"), ".service")
			if _, ok := grantPolicies[consumer]; ok {
				return consumer
			}
		}
	}
	return ""
}

// This handler is served only on the peer-authenticated Unix listener, never on the public router.
func (s *Server) grantBroker(w http.ResponseWriter, r *http.Request) {
	peer, ok := r.Context().Value(grantPeerKey{}).(grantPeer)
	if !ok || (peer.UID != 0 && peer.UID != uint32(os.Getuid())) {
		fail(w, 403, "external.consumerDenied")
		return
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", peer.PID))
	consumer := peerConsumer(string(raw))
	if err != nil || consumer == "" {
		fail(w, 403, "external.consumerDenied")
		return
	}
	s.serveGrantToken(w, r, consumer)
}

func (s *Server) serveGrantToken(w http.ResponseWriter, r *http.Request, consumer string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" || r.URL.Path != "/v1/token" {
		fail(w, 404, "Not found")
		return
	}
	var body struct {
		GrantID string `json:"grantId"`
		Owner   string `json:"owner"`
	}
	if !decode(w, r, &body) {
		return
	}
	s.external.Lock()
	defer s.external.Unlock()
	g, err := s.Store.ExternalGrant(body.GrantID)
	if err != nil || g.Consumer != consumer {
		fail(w, 403, "external.grantUnavailable")
		return
	}
	policy, installation, ok := grantInstallation(consumer, g.Capability)
	owner, err := s.Store.ExternalConnection(g.ConnectionID)
	if !ok || err != nil || owner.Username != body.Owner || policy.Scope != g.Scope || owner.Provider != policy.Provider {
		fail(w, 403, "external.grantUnavailable")
		return
	}
	if g.Status == "reconnect_required" {
		fail(w, 409, "external.reconnectRequired")
		return
	}
	if g.Status != "active" {
		fail(w, 403, "external.grantUnavailable")
		return
	}
	config, err := s.Store.ExternalConfig(owner.Provider)
	if err != nil || !config.Enabled {
		fail(w, 403, "external.grantUnavailable")
		return
	}
	id, err := s.checkedExternalOwner(r.Context(), owner)
	if err != nil {
		fail(w, 403, "external.accountUnavailable")
		return
	}
	if id.Epoch != g.Epoch || g.Revision != config.Revision || installation != g.Installation {
		if s.Store.SetGrantStatus(g.ID, "reconnect_required") != nil {
			fail(w, 503, "external.unavailable")
			return
		}
		fail(w, 409, "external.reconnectRequired")
		return
	}
	updated, err := external.Refresh(r.Context(), s.external.client, config.ClientID, config.ClientSecret, g.Token)
	if err != nil {
		if errors.Is(err, external.ErrReconnect) {
			if s.Store.SetGrantStatus(g.ID, "reconnect_required") != nil {
				fail(w, 503, "external.unavailable")
				return
			}
			fail(w, 409, "external.reconnectRequired")
		} else {
			fail(w, 503, "external.refreshUnavailable")
		}
		return
	}
	// Recheck dynamic authorization after the network call before releasing credentials.
	_, currentInstallation, enabled := grantInstallation(consumer, g.Capability)
	currentOwner, e := s.checkedExternalOwner(r.Context(), owner)
	if !enabled || currentInstallation != installation || e != nil || currentOwner.Epoch != g.Epoch {
		fail(w, 403, "external.grantUnavailable")
		return
	}
	g.Token = updated
	if err = s.Store.UpdateExternalGrant(g); err != nil {
		fail(w, 503, "external.unavailable")
		return
	}
	jsonResponse(w, 200, map[string]any{"accessToken": updated.AccessToken, "tokenType": "Bearer", "expiresAt": updated.Expiry.UTC(), "scope": g.Scope})
}

func (s *Server) ServeGrantBroker(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(path)
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	server := &http.Server{Handler: http.HandlerFunc(s.grantBroker), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 40 * time.Second, MaxHeaderBytes: 4096,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			u, ok := c.(*net.UnixConn)
			if !ok {
				return ctx
			}
			raw, err := u.SyscallConn()
			if err != nil {
				return ctx
			}
			var cred *unix.Ucred
			var credErr error
			err = raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
			if err != nil || credErr != nil || cred == nil {
				return ctx
			}
			return context.WithValue(ctx, grantPeerKey{}, grantPeer{PID: cred.Pid, UID: cred.Uid})
		},
	}
	server.SetKeepAlivesEnabled(false)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			server.Close()
		case <-done:
		}
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
