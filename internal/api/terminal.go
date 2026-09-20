package api

import (
	"context"
	"github.com/coder/websocket"
	"net/http"
	"net/url"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/modules"
	"time"
)

func (s *Server) terminal(w http.ResponseWriter, r *http.Request) {
	id := r.Context().Value(identityKey{}).(auth.Identity)
	factory := s.ModuleClient
	if factory == nil {
		factory = modules.Client
	}
	moduleClient, moduleErr := factory("terminal")
	if moduleErr != nil {
		fail(w, 404, "Module is not installed or is disabled")
		return
	}
	if id.Role != "admin" {
		fail(w, 403, "Administrator permissions required")
		return
	}
	agentClient := *moduleClient
	agentClient.Timeout = 0
	upstream, _, err := websocket.Dial(r.Context(), "ws://agent/terminal?user="+url.QueryEscape(id.Username), &websocket.DialOptions{HTTPClient: &agentClient})
	if err != nil {
		fail(w, 503, "Terminal unavailable")
		return
	}
	defer upstream.CloseNow()
	client, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer client.CloseNow()
	client.SetReadLimit(65536)
	upstream.SetReadLimit(65536)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	copy := func(dst, src *websocket.Conn) {
		defer cancel()
		for {
			kind, b, e := src.Read(ctx)
			if e != nil {
				return
			}
			cx, c := context.WithTimeout(ctx, 5*time.Second)
			e = dst.Write(cx, kind, b)
			c()
			if e != nil {
				return
			}
		}
	}
	go copy(upstream, client)
	go copy(client, upstream)
	timer := time.NewTicker(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if _, e := s.Identity(r); e != nil {
				client.Close(websocket.StatusPolicyViolation, "session expired")
				return
			}
		}
	}
}
