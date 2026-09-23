package host

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops"
)

// Actions is the set of mutation actions this Go package owns, mirroring the
// host.py ACTIONS subset ported in GO-03. folder.permissions and the nfs.*/smb.*
// actions are intentionally excluded (they stay legacy until GO-06/GO-07).
var Actions = map[string]bool{
	"system.poweroff": true,
	"system.reboot":   true,
	"service.start":   true,
	"service.stop":    true,
	"service.restart": true,
	"service.enable":  true,
	"service.disable": true,
	"updates.refresh": true,
	"updates.install": true,
	"updates.repair":  true,
}

// Plan reproduces host.plan for the ported actions: it validates the target,
// gathers the current state, and returns the plan with a fingerprint over
// (action, params, state) so a stale plan is rejected at execute time.
func Plan(ctx context.Context, action string, params map[string]any) (json.RawMessage, error) {
	if !Actions[action] {
		return nil, reject("Unknown system operation")
	}
	target, _ := params["target"].(string)
	var state any = map[string]any{}
	var details []any

	switch {
	case action == "system.poweroff" || action == "system.reboot":
		target = "NAS"
		bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil {
			return nil, reject("Unknown system operation")
		}
		state = strings.TrimSpace(string(bootID))
		details = []any{action}
	case strings.HasPrefix(action, "service."):
		unit, err := service(ctx, target)
		if err != nil {
			return nil, err
		}
		target = unit
		out, err := systemops.Command(ctx, []string{"systemctl", "show", "--property=ActiveState,UnitFileState,LoadState", target}, systemops.CommandOptions{})
		if err != nil {
			return nil, err
		}
		state = string(out)
		details = []any{target, strings.SplitN(action, ".", 2)[1]}
	case action == "updates.repair":
		target = "OS UPDATE"
		out, err := systemops.Command(ctx, []string{"dpkg", "--audit"}, systemops.CommandOptions{Timeout: 20 * time.Second})
		if err != nil {
			return nil, err
		}
		audit := string(out)
		if strings.TrimSpace(audit) == "" {
			return nil, reject("No incomplete packages reported")
		}
		state = audit
		details = []any{"Finish configuring interrupted system packages", truncate(audit, 8192)}
	case strings.HasPrefix(action, "updates."):
		target = "OS UPDATE"
		packages, _, err := simulateUpgrade(ctx)
		if err != nil {
			return nil, err
		}
		// State mirrors query("updates","") — the full result map — so the
		// fingerprint matches the Python plan exactly.
		state = map[string]any{
			"packages":       packages,
			"packageDetails": detailList(packages),
			"rebootRequired": rebootRequired(),
		}
		if action == "updates.install" {
			details = toAnySlice(packages)
			if len(details) == 0 {
				return nil, reject("No updates available")
			}
		} else {
			details = []any{"Refresh available package lists"}
		}
	}

	fp, err := fingerprint(action, params, state)
	if err != nil {
		return nil, err
	}
	return marshal(map[string]any{
		"target":       target,
		"details":      details,
		"confirmation": target,
		"fingerprint":  fp,
	})
}

// Execute reproduces host.execute for the ported actions. Progress stages are
// emitted through the reporter for the long-running package operations, exactly
// as the Python common.command does under PANASMS_OPERATION.
func Execute(ctx context.Context, action string, params map[string]any, r *systemops.Reporter) (json.RawMessage, error) {
	if !Actions[action] {
		return nil, reject("Unknown system operation")
	}
	target, _ := params["target"].(string)

	switch {
	case action == "system.poweroff" || action == "system.reboot":
		verb := strings.SplitN(action, ".", 2)[1]
		_, err := systemops.Command(ctx, []string{
			"systemd-run", "--unit=panasms-power-request", "--on-active=5s",
			"--timer-property=AccuracySec=1s", "/usr/bin/systemctl", "--no-block", verb,
		}, systemops.CommandOptions{Operation: true, Reporter: r})
		if err != nil {
			return nil, err
		}
		return marshal(map[string]any{"message": "Power operation scheduled"})

	case strings.HasPrefix(action, "service."):
		verb := strings.SplitN(action, ".", 2)[1]
		if _, err := systemops.Command(ctx, []string{"systemctl", verb, target}, systemops.CommandOptions{Operation: true, Reporter: r}); err != nil {
			return nil, err
		}
		out, err := systemops.Command(ctx, []string{"systemctl", "show", "--property=ActiveState,UnitFileState", "--value", target}, systemops.CommandOptions{})
		if err != nil {
			return nil, err
		}
		return marshal(map[string]any{"message": string(out)})

	case action == "updates.repair":
		if _, err := systemops.Command(ctx, []string{"dpkg", "--configure", "-a", "--force-confold"}, systemops.CommandOptions{Timeout: 86400 * time.Second, Operation: true, Reporter: r}); err != nil {
			return nil, err
		}
		out, err := systemops.Command(ctx, []string{"dpkg", "--audit"}, systemops.CommandOptions{Timeout: 20 * time.Second})
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(string(out)) != "" {
			return nil, reject("Some packages still require repair; inspect the system journal")
		}
	case action == "updates.refresh":
		if _, err := systemops.Command(ctx, []string{"apt-get", "update"}, systemops.CommandOptions{Timeout: 1800 * time.Second, Operation: true, Reporter: r}); err != nil {
			return nil, err
		}
	case action == "updates.install":
		if _, err := systemops.Command(ctx, []string{"apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "upgrade"}, systemops.CommandOptions{Timeout: 86400 * time.Second, Operation: true, Reporter: r}); err != nil {
			return nil, err
		}
	}
	return marshal(map[string]any{"message": "Done", "rebootRequired": rebootRequired()})
}

// rebootRequired reports whether a package operation left the reboot flag.
func rebootRequired() bool {
	_, err := os.Stat("/run/reboot-required")
	return err == nil
}

// fingerprint decodes params/state through json.Number and computes the
// canonical fingerprint, matching common.fingerprint. Values already coming
// from a json.Number-decoded request keep integer precision; state built here
// from Go values is round-tripped through Decode for the same guarantee.
func fingerprint(action string, params map[string]any, state any) (string, error) {
	canonParams, err := numberize(params)
	if err != nil {
		return "", err
	}
	canonState, err := numberize(state)
	if err != nil {
		return "", err
	}
	m, _ := canonParams.(map[string]any)
	return systemops.Fingerprint(action, m, canonState)
}

// numberize round-trips a value through JSON with json.Number decoding so any
// integers are represented identically to a request decoded by ReadRequest.
func numberize(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := systemops.Decode(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func detailList(packages []string) []map[string]any {
	out := make([]map[string]any, 0, len(packages))
	for _, line := range packages {
		out = append(out, packageDetail(line))
	}
	return out
}

func toAnySlice(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
