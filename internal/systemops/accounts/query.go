package accounts

import (
	"context"
	"encoding/json"
	"os/exec"
	"sort"
	"strconv"
	"time"
)

// Query returns account inventory or the selected account with keys and SMB status.
func Query(ctx context.Context, target string) (json.RawMessage, error) {

	users, err := getpwall()
	if err != nil {
		return nil, err
	}
	groups, err := getgrall()
	if err != nil {
		return nil, err
	}
	db, err := readPolicy()
	if err != nil {
		return nil, err
	}
	shellList, err := shells()
	if err != nil {
		return nil, err
	}

	userViews := make([]map[string]any, 0, len(users))
	for _, u := range users {
		view, err := userView(u, users, groups, db, shellList)
		if err != nil {
			return nil, err
		}
		userViews = append(userViews, view)
	}

	if target != "" {
		for _, view := range userViews {
			if view["username"] != target {
				continue
			}
			view["keys"] = []Key{}
			if view["category"] != "service" {
				status, err := samba(ctx, "status", target, "")
				if err != nil {
					return nil, err
				}
				view["smb"] = status
				keys, err := keyOperation(ctx, target, KeyRequest{Action: "list"})
				if err != nil {
					view["keysError"] = "SSH keys could not be read"
				} else {
					view["keys"] = keys
				}
			}
			return marshal(view)
		}
		return nil, reject("User not found")
	}
	lo, hi, err := bounds("GID")
	if err != nil {
		return nil, err
	}
	groupViews := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		members := map[string]bool{}
		for _, m := range g.Members {
			members[m] = true
		}
		primaryMembers := []string{}
		for _, u := range users {
			if u.GID == g.GID {
				members[u.Name] = true
				primaryMembers = append(primaryMembers, u.Name)
			}
		}
		memberList := make([]string, 0, len(members))
		for m := range members {
			memberList = append(memberList, m)
		}
		sort.Strings(memberList)
		groupViews = append(groupViews, map[string]any{
			"name":           g.Name,
			"gid":            g.GID,
			"members":        memberList,
			"primaryMembers": primaryMembers,
			"editable":       (lo <= g.GID && g.GID <= hi) || g.Name == "sudo",
			"system":         !(lo <= g.GID && g.GID <= hi),
		})
	}

	return marshal(map[string]any{
		"users":          userViews,
		"groups":         groupViews,
		"shells":         shellList,
		"passwordPolicy": "Linux PAM / passwd",
		"sshAvailable":   sshdInstalled(),
	})
}

// userView builds one user's list entry, mirroring the dict accounts.query()
// assembles per user (including the merged shadow state via **state).
func userView(u passwdUser, users []passwdUser, groups []groupEntry, db policyDB, shellList []string) (map[string]any, error) {
	memberGroups := []string{}
	primaryGroup := strconv.Itoa(u.GID)
	primarySet := false
	for _, g := range groups {
		if g.GID == u.GID {
			if !primarySet {
				primaryGroup = g.Name
				primarySet = true
			}
			memberGroups = append(memberGroups, g.Name)
			continue
		}
		if contains(g.Members, u.Name) {
			memberGroups = append(memberGroups, g.Name)
		}
	}

	category := "user"
	if contains(memberGroups, "sudo") {
		category = "admin"
	}
	if normal(users, u) != nil {
		category = "service"
	}

	policy := policyEntry(db, u)
	state, err := shadow(u.Name)
	if err != nil {
		return nil, err
	}
	disabled, _ := policy["disabled"].(bool)
	isExpired := expired(state) || passwordInactive(state.LastChange, state.MaxDays, state.InactiveDays)

	panelDefault := category == "admin"
	panel := category != "service" && policyBool(policy, "panel", panelDefault)
	ssh := policyBool(policy, "ssh", inShells(shellList, u.Shell))

	expiryStr := ""
	if disabled {
		if v, ok := policy["expiry"].(string); ok {
			expiryStr = v
		}
	} else if state.ExpiryDay >= 0 {
		expiryStr = epochDay(state.ExpiryDay)
	}

	reason := "Local account in the Linux user UID range"
	if category == "service" {
		reason = "Protected or ambiguous system account"
	}

	name := ""
	if parts := splitGecos(u.Gecos); len(parts) > 0 {
		name = parts[0]
	}

	view := map[string]any{
		"username":     u.Name,
		"name":         name,
		"uid":          u.UID,
		"gid":          u.GID,
		"home":         u.Dir,
		"shell":        u.Shell,
		"category":     category,
		"groups":       memberGroups,
		"primaryGroup": primaryGroup,
		"panel":        panel,
		"disabled":     disabled,
		"expired":      isExpired,
		"ssh":          ssh,
		"expiry":       expiryStr,
		"reason":       reason,
	}
	// Merge shadow state (**state in Python) so passwordStatus, aging fields and
	// forcePasswordChange are exposed alongside the account fields.
	view["passwordStatus"] = state.PasswordStatus
	view["lastChange"] = state.LastChange
	view["minDays"] = state.MinDays
	view["maxDays"] = state.MaxDays
	view["warnDays"] = state.WarnDays
	view["inactiveDays"] = state.InactiveDays
	view["expiryDay"] = state.ExpiryDay
	view["forcePasswordChange"] = state.ForcePasswordChange
	return view, nil
}

// epochDay formats a day count since the epoch as an ISO date, matching the
// Python str(date(1970,1,1) + timedelta(days=day)).
func epochDay(day int) string {
	return time.Unix(int64(day)*86400, 0).UTC().Format("2006-01-02")
}

// splitGecos splits the GECOS field on commas, matching pw_gecos.split(',').
func splitGecos(gecos string) []string {
	return splitComma(gecos)
}

func splitComma(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func sshdInstalled() bool {
	_, err := exec.LookPath("sshd")
	return err == nil
}
