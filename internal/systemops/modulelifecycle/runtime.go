package modulelifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"panasms.local/backend/internal/systemops"
)

type command func(context.Context, []string, systemops.CommandOptions) ([]byte, error)
type healthCheck func(context.Context, string) (map[string]any, error)

func unit(id string) string { return "panasms-module-" + id + ".service" }

func unitContent(root string, manifest Manifest) ([]byte, error) {
	id := text(manifest, "id")
	if err := identifier(id); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(root) || strings.ContainsAny(root, "\r\n\t %\\\"") {
		return nil, reject("Invalid module installation path")
	}
	if text(manifest, "service") != "bin/server" {
		return nil, reject("Unknown service format")
	}
	privileges := "yes"
	if manifest["userShell"] == true {
		privileges = "no"
	}
	return []byte(fmt.Sprintf(`[Unit]
Description=PaNasMs module %s
After=local-fs.target
[Service]
User=root
Group=panasms
AmbientCapabilities=CAP_SETUID CAP_SETGID
EnvironmentFile=/etc/panasms/panasms.env
Environment=PYTHONPATH=/usr/lib/panasms/management
ExecStart=%s/%s/bin/server
Restart=on-failure
RestartSec=3
RuntimeDirectory=panasms-modules
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
KillMode=control-group
Environment=PANASMS_MAINTENANCE_LOCK=/run/lock/panasms-maintenance.lock
UMask=0077
NoNewPrivileges=%s
PrivateTmp=yes
LockPersonality=yes
[Install]
WantedBy=multi-user.target
`, id, root, id, privileges)), nil
}

func writeUnit(root, units string, manifest Manifest, owner uint32) error {
	if text(manifest, "service") == "" {
		return nil
	}
	content, err := unitContent(root, manifest)
	if err != nil {
		return err
	}
	directory, err := trustedDirectory(units, owner)
	if err != nil {
		return err
	}
	defer directory.Close()
	return atomicAt(directory, unit(text(manifest, "id")), content, 0644, owner)
}

func health(ctx context.Context, id string) (map[string]any, error) {
	if err := identifier(id); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/run/panasms-modules/"+id+".sock")
	}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://module/health", nil)
	if err != nil {
		return nil, err
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, reject("Module service failed to start: " + id)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if len(raw) > 8192 || systemops.Decode(raw, &result) != nil || result == nil {
		return nil, reject("Cannot check active tasks in module " + id)
	}
	return result, nil
}

func requireIdle(ctx context.Context, manifest Manifest, check healthCheck, run command) error {
	if manifest["enabled"] != true || text(manifest, "service") == "" {
		return nil
	}
	id := text(manifest, "id")
	result, err := check(ctx, id)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		state, probeErr := run(ctx, []string{"systemctl", "is-active", unit(id)}, systemops.CommandOptions{Accepted: []int{0, 3, 4}})
		if probeErr != nil {
			return probeErr
		}
		switch strings.TrimSpace(string(state)) {
		case "inactive", "failed", "unknown":
			return nil
		}
		return reject("Cannot check active tasks in module " + id)
	}
	if err != nil {
		return err
	}
	version, valid := integer(result["maintenanceVersion"])
	if !valid || version != 1 {
		return reject("Module " + id + " does not support coordinated maintenance. Finish its tasks and stop its service in System services before retrying.")
	}
	active, valid := integer(result["active"])
	if !valid || active != 0 {
		return reject("Module " + id + " is busy: close the terminal or finish file transfers")
	}
	return nil
}

func startModule(ctx context.Context, manifest Manifest, run command, check healthCheck, reporter *systemops.Reporter) error {
	if text(manifest, "service") == "" {
		return nil
	}
	id := text(manifest, "id")
	if _, err := run(ctx, []string{"systemctl", "enable", "--now", unit(id)}, systemops.CommandOptions{Operation: true, Reporter: reporter}); err != nil {
		return err
	}
	for attempt := 0; attempt < 20; attempt++ {
		if _, err := check(ctx, id); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return reject("Module service failed to start: " + id)
}

func queryRegistry(s store, core string, member bool) (json.RawMessage, error) {
	registry, err := s.registry()
	if err != nil {
		return nil, err
	}
	result, err := listModules(registry, core, member)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
