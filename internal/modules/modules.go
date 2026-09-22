package modules

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
)

var Root = "/var/lib/panasms-modules"
var ID = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)

type Manifest struct {
	Installation string            `json:"installation"`
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Version      string            `json:"version"`
	Enabled      bool              `json:"enabled"`
	Widgets      map[string][2]int `json:"widgets"`
	Files        map[string]string `json:"files"`
}

func Read() map[string]Manifest {
	raw, err := os.ReadFile(filepath.Join(Root, "registry.json"))
	result := map[string]Manifest{}
	if err != nil || json.Unmarshal(raw, &result) != nil {
		return map[string]Manifest{}
	}
	return result
}
func Enabled(id string) bool { m, ok := Read()[id]; return ok && m.Enabled && ID.MatchString(id) }
func Client(id string) (*http.Client, error) {
	if !Enabled(id) {
		return nil, errors.New("module disabled")
	}
	return &http.Client{Transport: &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/run/panasms-modules/"+id+".sock")
	}}}, nil
}

func Known() map[string]Manifest {
	raw, err := os.ReadFile(filepath.Join(Root, "catalog.json"))
	result := map[string]Manifest{}
	if err == nil {
		_ = json.Unmarshal(raw, &result)
	}
	for id, m := range Read() {
		result[id] = m
	}
	return result
}
