package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"panasms.local/backend/internal/oled"
)

func (s *Server) monitorUpdates(ctx context.Context) *oled.Task {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://agent/update-feed", nil)
	if err != nil {
		return nil
	}
	resp, err := s.Agent.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var update struct {
		Available bool   `json:"available"`
		Version   string `json:"version"`
		Phase     string `json:"phase"`
		ID        string `json:"id"`
		Error     string `json:"error"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&update) != nil {
		return nil
	}
	if update.Available {
		s.Store.Inform("update:available:"+update.Version, "PaNasMs update available: "+update.Version)
	}
	if update.ID != "" {
		switch update.Phase {
		case "complete", "rolled-back", "failed", "recovery-required":
			s.Store.Inform("update:result:"+update.ID, "PaNasMs update: "+update.Phase+" · "+update.Error)
		}
	}
	switch update.Phase {
	case "queued", "checking", "downloading", "preparing", "backing-up", "installing", "verifying", "rolling-back":
		return &oled.Task{ID: "update:" + update.ID, Kind: "update", State: update.Phase}
	}
	return nil
}
