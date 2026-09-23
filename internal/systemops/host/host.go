// Package host is the Go port of backend/management/host.py's system, service,
// journal, package-update and power operations (GO-03). It reproduces the exact
// command arguments, timeouts, protected-service rules and human-readable
// messages of the Python layer so the panel behaves identically.
//
// Deliberately NOT ported here (kept on the legacy Python dispatcher until their
// own tasks own them): folder.permissions and the NFS/SMB export/mount actions
// (network_mounts), which move in GO-06/GO-07. HTTP port changes are owned
// separately by systemops/webaccess.
package host

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops"
)

// serviceUnit matches host.py's service() unit-name rule.
var serviceUnit = regexp.MustCompile(`^[a-zA-Z0-9_.@:-]+\.service$`)

// protectedPrefixes are unit-name prefixes host.py refuses to act on through
// the panel, protecting the OS and PaNasMs itself from panel-driven changes.
var protectedPrefixes = []string{"panasms-", "ssh", "systemd-", "dbus", "network", "NetworkManager", "getty"}

// packageLine matches "Inst "/"Remv " lines emitted by apt-get --simulate.
var packageLine = regexp.MustCompile(`^(Inst|Remv) (\S+)(?: \[([^\]]+)\])?(?: \((\S+) (.*)\))?`)

// service validates and returns a systemd unit name, reproducing host.service():
// it must look like a *.service unit, must not be a protected unit, and must be
// loaded. It runs systemctl to confirm the load state.
func service(ctx context.Context, value string) (string, error) {
	if !serviceUnit.MatchString(value) {
		return "", reject("Select a systemd service")
	}
	for _, p := range protectedPrefixes {
		if strings.HasPrefix(value, p) {
			return "", reject("This service is protected from changes through the panel")
		}
	}
	out, err := systemops.Command(ctx, []string{"systemctl", "show", "--property=LoadState", "--value", value}, systemops.CommandOptions{})
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(out)) != "loaded" {
		return "", reject("Service is not loaded")
	}
	return value, nil
}

func reject(msg string) error { return &systemops.Rejected{Message: msg} }

// Query serves the services/journal/power/updates views, mirroring host.query.
func Query(ctx context.Context, view, target string) (json.RawMessage, error) {
	switch view {
	case "nfs":
		// nfs export listing stays legacy (GO-07); this Go path is not routed
		// for it, but guard anyway.
		return nil, reject("Unknown system query")
	case "power":
		return powerQuery(ctx)
	case "services":
		return servicesQuery(ctx)
	case "journal":
		return journalQuery(ctx, target)
	case "updates":
		return updatesQuery(ctx)
	}
	return nil, reject("Unknown system query")
}

func powerQuery(ctx context.Context) (json.RawMessage, error) {
	out, err := systemops.Command(ctx, []string{"vcgencmd", "get_throttled"}, systemops.CommandOptions{})
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(out))
	// raw looks like "throttled=0x0"; parse the hex after '='.
	parts := strings.SplitN(raw, "=", 2)
	if len(parts) != 2 {
		return nil, reject("Unknown system query")
	}
	value, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(parts[1]), "0x"), 16, 64)
	if err != nil {
		return nil, reject("Unknown system query")
	}
	return marshal(map[string]any{
		"throttled":        raw,
		"undervoltage":     value&1 != 0,
		"throttling":       value&4 != 0,
		"pastUndervoltage": value&(1<<16) != 0,
	})
}

func servicesQuery(ctx context.Context) (json.RawMessage, error) {
	unitsRaw, err := systemops.Command(ctx, []string{"systemctl", "list-units", "--type=service", "--all", "--output=json"}, systemops.CommandOptions{})
	if err != nil {
		return nil, err
	}
	filesRaw, err := systemops.Command(ctx, []string{"systemctl", "list-unit-files", "--type=service", "--output=json"}, systemops.CommandOptions{})
	if err != nil {
		return nil, err
	}
	var units []map[string]any
	if err := systemops.Decode(unitsRaw, &units); err != nil {
		return nil, reject("Unknown system query")
	}
	var files []map[string]any
	if err := systemops.Decode(filesRaw, &files); err != nil {
		return nil, reject("Unknown system query")
	}
	states := map[string]any{}
	for _, row := range files {
		if uf, ok := row["unit_file"].(string); ok {
			states[uf] = row["state"]
		}
	}
	for _, unit := range units {
		name, _ := unit["unit"].(string)
		if s, ok := states[name]; ok {
			unit["enabled"] = s
		} else {
			unit["enabled"] = "unknown"
		}
	}
	return marshal(map[string]any{"services": units})
}

func journalQuery(ctx context.Context, target string) (json.RawMessage, error) {
	args := []string{"journalctl", "--no-pager", "--output=json", "--lines=300", "--reverse"}
	filters := map[string]any{}
	if strings.HasPrefix(target, "{") {
		if err := systemops.Decode([]byte(target), &filters); err != nil {
			return nil, reject("Invalid request")
		}
	} else {
		filters["unit"] = target
	}
	unit, _ := filters["unit"].(string)

	priority := int64(7)
	if p, ok := filters["priority"]; ok {
		n, err := toInt(p)
		if err != nil {
			return nil, reject("Number outside the allowed range")
		}
		priority = n
	}
	if _, err := systemops.Integer(priority, 0, 7); err != nil {
		return nil, err
	}
	args = append(args, "--priority", strconv.FormatInt(priority, 10))

	since := "24h"
	if s, ok := filters["since"].(string); ok {
		since = s
	}
	sinceArg := map[string]string{"1h": "1 hour ago", "24h": "1 day ago", "7d": "7 days ago"}
	if since != "all" {
		mapped, ok := sinceArg[since]
		if !ok {
			return nil, reject("Invalid period")
		}
		args = append(args, "--since", mapped)
	}

	boot := "all"
	if b, ok := filters["boot"].(string); ok {
		boot = b
	}
	switch boot {
	case "all":
	case "current":
		args = append(args, "--boot", "0")
	case "previous":
		args = append(args, "--boot", "-1")
	default:
		return nil, reject("Invalid boot selection")
	}

	if unit != "" {
		if !serviceUnit.MatchString(unit) {
			return nil, reject("Invalid service")
		}
		args = append(args, "--unit", unit)
	}

	out, err := systemops.Command(ctx, args, systemops.CommandOptions{})
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		message := ""
		if m, ok := row["MESSAGE"]; ok {
			message = truncate(toString(m), 8192)
		}
		rows = append(rows, map[string]any{
			"time":     row["__REALTIME_TIMESTAMP"],
			"priority": row["PRIORITY"],
			"unit":     row["_SYSTEMD_UNIT"],
			"message":  message,
		})
	}
	return marshal(map[string]any{"entries": rows})
}

func updatesQuery(ctx context.Context) (json.RawMessage, error) {
	packages, details, err := simulateUpgrade(ctx)
	if err != nil {
		return nil, err
	}
	return marshal(map[string]any{
		"packages":       packages,
		"packageDetails": details,
		"rebootRequired": rebootRequired(),
	})
}

// simulateUpgrade runs `apt-get --simulate upgrade` and returns the Inst/Remv
// lines and their parsed detail records, matching host.query("updates").
func simulateUpgrade(ctx context.Context) ([]string, []map[string]any, error) {
	out, err := systemops.Command(ctx, []string{"apt-get", "--simulate", "upgrade"}, systemops.CommandOptions{Timeout: 60 * time.Second})
	if err != nil {
		return nil, nil, err
	}
	packages := []string{}
	details := []map[string]any{}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Inst ") || strings.HasPrefix(line, "Remv ") {
			packages = append(packages, line)
			details = append(details, packageDetail(line))
		}
	}
	return packages, details, nil
}

func packageDetail(line string) map[string]any {
	m := packageLine.FindStringSubmatch(line)
	if m == nil {
		return map[string]any{"name": line, "installed": "", "available": "", "source": "", "action": "unknown"}
	}
	action := "install"
	if m[1] == "Remv" {
		action = "remove"
	}
	return map[string]any{"name": m[2], "installed": m[3], "available": m[4], "source": m[5], "action": action}
}

func marshal(v any) (json.RawMessage, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	data, _ := json.Marshal(v)
	return string(data)
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n])
	}
	return s
}

func toInt(v any) (int64, error) {
	switch n := v.(type) {
	case json.Number:
		return n.Int64()

	}
	return 0, reject("Number outside the allowed range")
}
