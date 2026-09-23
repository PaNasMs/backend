package worker

import (
	"context"
	"encoding/json"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/accounts"
	"panasms.local/backend/internal/systemops/host"
	"panasms.local/backend/internal/systemops/webaccess"
	"strings"
	"time"
)

func recoverOperation(ctx context.Context, req *systemops.Request) (json.RawMessage, error) {
	checks := []map[string]any{}
	route := "/"
	message := "Review the current state below. The interrupted operation has not been repeated."
	var next any
	add := func(label string, value any) { checks = append(checks, map[string]any{"label": label, "value": value}) }
	target, _ := req.Params["target"].(string)
	switch {
	case accounts.IsNative(req.Action):
		route = "/users"
		if _, err := systemops.Name(target); err != nil {
			return nil, err
		}
		table := "passwd"
		if strings.HasPrefix(req.Action, "group.") {
			table = "group"
		}
		raw, err := systemops.Command(ctx, []string{"getent", table, target}, systemops.CommandOptions{Accepted: []int{0, 2}})
		if err != nil {
			return nil, err
		}
		state := "Absent"
		if len(raw) > 0 {
			state = "Present"
		}
		add("Account", state)
		if table == "passwd" && len(raw) > 0 {
			fields := strings.Split(strings.TrimSpace(string(raw)), ":")
			if len(fields) >= 6 {
				add("Home folder", fields[5])
			}
		}
		if req.Action == "user.password" {
			message = "A password change cannot be verified from stored credentials. Sign in or set a new password through Users."
		}
	case req.Action == "system.web-port":
		route = "/settings/general"
		raw, err := webaccess.Default().Query()
		if err != nil {
			return nil, err
		}
		add("Web access", raw)
		message = "Check the active address before applying another port change."
	case strings.HasPrefix(req.Action, "service."):
		route = "/system/services"
		if _, err := host.Plan(ctx, req.Action, req.Params); err != nil {
			return nil, err
		}
		raw, err := systemops.Command(ctx, []string{"systemctl", "show", "--property=ActiveState,SubState,UnitFileState", "--", target}, systemops.CommandOptions{Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		add("Service", string(raw))
	case strings.HasPrefix(req.Action, "updates."):
		route = "/system/updates"
		raw, err := systemops.Command(ctx, []string{"dpkg", "--audit"}, systemops.CommandOptions{Timeout: 20 * time.Second})
		if err != nil {
			return nil, err
		}
		value := string(raw)
		if strings.TrimSpace(value) != "" {
			next = "updates.repair"
		} else {
			value = "No incomplete packages reported"
		}
		if len(value) > 8192 {
			value = value[:8192]
		}
		add("Package database", value)
		message = "Do not restart package installation blindly. Review package status and refresh the update list; incomplete packages require repair before another upgrade."
	case req.Action == "system.reboot" || req.Action == "system.poweroff":
		route = "/system/services"
		add("System", "The system is reachable")
		message = "Power actions are never replayed automatically. System availability alone does not prove whether the previous reboot completed."
	default:
		return nil, systemops.ErrNoRoute
	}
	return json.Marshal(map[string]any{"message": message, "checks": checks, "route": route, "recoveryAction": next})
}
