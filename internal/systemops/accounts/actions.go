package accounts

import (
	"context"
	"encoding/json"
	"os"

	"panasms.local/backend/internal/systemops"
)

var nativeActions = map[string]bool{
	"group.create": true, "group.edit": true, "group.delete": true,
	"user.create": true, "user.edit": true, "user.security": true, "user.identity": true,
	"user.home": true, "user.password": true, "user.delete": true,
	"user.key.add": true, "user.key.delete": true, "user.session.end": true,
}

// IsNative reports whether this package implements action (as
// opposed to the accounts actions that stay on the legacy worker).
func IsNative(action string) bool { return nativeActions[action] }

// Plan reproduces accounts.plan for the natively-handled actions. It validates
// the target and gathers the same state accounts.plan does, so the fingerprint
// matches the Python plan exactly and a stale plan is rejected at execute time.
func Plan(ctx context.Context, action string, params map[string]any, actor string) (json.RawMessage, error) {
	if !nativeActions[action] {
		return nil, reject("Unknown user operation")
	}
	users, err := getpwall()
	if err != nil {
		return nil, err
	}
	groups, err := getgrall()
	if err != nil {
		return nil, err
	}

	target, err := targetName(params)
	if err != nil {
		return nil, err
	}
	details := []any{target}

	switch action {
	case "user.create", "user.edit", "user.security", "user.identity", "user.home", "user.password", "user.delete", "group.edit":
		extra, err := validateAccount(action, params, actor, target, users, groups)
		if err != nil {
			return nil, err
		}
		details = append(details, extra...)
	case "group.create":
		if _, ok := getgrnam(groups, target); ok {
			return nil, reject("Group already exists")
		}
	case "group.delete":
		g, ok := getgrnam(groups, target)
		if !ok {
			return nil, reject("Invalid name")
		}
		lo, hi, err := bounds("GID")
		if err != nil {
			return nil, err
		}
		if !(lo <= g.GID && g.GID <= hi) {
			return nil, reject("Service group is protected")
		}
		usedByPrimary := false
		for _, u := range users {
			if u.GID == g.GID {
				usedByPrimary = true
			}
		}
		if len(g.Members) > 0 || usedByPrimary {
			return nil, reject("The group is used by users")
		}
	case "user.key.add", "user.key.delete":
		if _, err := account(users, target); err != nil {
			return nil, err
		}
		if action == "user.key.add" {
			key, _ := params["key"].(string)
			if len(key) == 0 || len(key) > 16384 {
				return nil, reject("Enter an OpenSSH public key")
			}
		} else {
			keyID, _ := params["keyId"].(string)
			keys, err := keyOperation(ctx, target, KeyRequest{Action: "list"})
			if err != nil {
				return nil, err
			}
			found := false
			for _, k := range keys {
				if k.ID == keyID {
					found = true
				}
			}
			if !found {
				return nil, reject("Key not found")
			}
		}
		details = append(details, "Changing a key does not enable SSH or end existing SSH sessions")
	case "user.session.end":
		if _, err := account(users, target); err != nil {
			return nil, err
		}
		sessionID, _ := params["sessionId"].(string)
		list, err := listSessions(ctx, target)
		if err != nil {
			return nil, err
		}
		var found *session
		for i := range list {
			if list[i].ID == sessionID {
				found = &list[i]
			}
		}
		if found == nil {
			return nil, reject("SSH session has already ended")
		}
		details = append(details, "End SSH session: "+found.ID+" "+found.Address)
	}

	state, err := planState(ctx, action, target)
	if err != nil {
		return nil, err
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

// planState assembles the fingerprint state accounts.plan builds: the passwd/
// group/policy/shadow snapshot, plus keys for key actions and sessions for the
// session action.
func planState(ctx context.Context, action, target string) (map[string]any, error) {
	passwd, err := readFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	group, err := readFile("/etc/group")
	if err != nil {
		return nil, err
	}
	shadowText, err := readFile("/etc/shadow")
	if err != nil {
		return nil, err
	}
	db, err := readPolicy()
	if err != nil {
		return nil, err
	}
	state := map[string]any{
		"passwd": passwd,
		"group":  group,
		"policy": db,
		"shadow": shadowText,
	}
	if action == "user.key.add" || action == "user.key.delete" {
		keys, err := keyOperation(ctx, target, KeyRequest{Action: "list"})
		if err != nil {
			return nil, err
		}
		state["keys"] = keys
	}
	if action == "user.session.end" {
		list, err := listSessions(ctx, target)
		if err != nil {
			return nil, err
		}
		state["sessions"] = list
	}
	return state, nil
}

// Execute reproduces accounts.execute for the natively-handled actions.
func Execute(ctx context.Context, action string, params map[string]any, r *systemops.Reporter) (json.RawMessage, error) {
	if !nativeActions[action] {
		return nil, reject("Unknown user operation")
	}
	target, _ := params["target"].(string)

	switch action {
	case "user.create", "user.edit", "user.security", "user.identity", "user.home", "user.password", "user.delete", "group.edit":
		if err := executeAccount(ctx, action, params, r); err != nil {
			return nil, err
		}

	case "group.create":
		if _, err := systemops.Command(ctx, []string{"groupadd", "--", target}, systemops.CommandOptions{Operation: true, Reporter: r}); err != nil {
			return nil, err
		}
	case "group.delete":
		if _, err := systemops.Command(ctx, []string{"groupdel", "--", target}, systemops.CommandOptions{Operation: true, Reporter: r}); err != nil {
			return nil, err
		}
	case "user.key.add":
		key, _ := params["key"].(string)
		if _, err := keyOperation(ctx, target, KeyRequest{Action: "add", Key: key}); err != nil {
			return nil, err
		}
	case "user.key.delete":
		keyID, _ := params["keyId"].(string)
		if _, err := keyOperation(ctx, target, KeyRequest{Action: "delete", ID: keyID}); err != nil {
			return nil, err
		}
	case "user.session.end":
		sessionID, _ := params["sessionId"].(string)
		if err := terminate(ctx, target, sessionID); err != nil {
			return nil, err
		}
	}
	return marshal(map[string]any{"message": "Users and groups updated"})
}

// targetName validates the "target" param as a name, matching name(p["target"]).
func targetName(params map[string]any) (string, error) {
	target, _ := params["target"].(string)
	return systemops.Name(target)
}

// fingerprint decodes params/state through json.Number and computes the
// canonical fingerprint, matching common.fingerprint (secret keys excluded,
// integer precision preserved). See host.fingerprint for the same pattern.
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

func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
