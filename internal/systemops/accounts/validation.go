package accounts

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

func stringParam(p map[string]any, k string) string { s, _ := p[k].(string); return s }
func intParam(p map[string]any, k string, def int) (int, error) {
	v, ok := p[k]
	if !ok {
		return def, nil
	}
	switch n := v.(type) {
	case int:
		return n, nil
	case json.Number:
		i, err := n.Int64()
		if err == nil && int64(int(i)) == i {
			return int(i), nil
		}
	}
	return 0, reject("Expected an integer: " + k)
}
func stringList(p map[string]any, k string) ([]string, error) {
	v, ok := p[k]
	if !ok {
		return []string{}, nil
	}
	var list []string
	switch x := v.(type) {
	case []string:
		list = x
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, reject("Select " + k)
			}
			list = append(list, s)
		}
	default:
		return nil, reject("Select " + k)
	}
	set := map[string]bool{}
	for _, s := range list {
		set[s] = true
	}
	out := []string{}
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}
func displayName(p map[string]any) error {
	v, ok := p["name"]
	if !ok {
		return nil
	}
	s, ok := v.(string)
	if !ok || utf8.RuneCountInString(s) > 80 || strings.IndexFunc(s, func(r rune) bool { return r < 32 || r == ':' || r == ',' }) >= 0 {
		return reject("Invalid display name")
	}
	return nil
}
func password(p map[string]any) error {
	s, ok := p["password"].(string)
	if !ok || s == "" || utf8.RuneCountInString(s) > 4096 || strings.ContainsAny(s, "\r\n\x00") {
		return reject("Enter your password")
	}
	return nil
}
func selectedGroups(p map[string]any, groups []groupEntry) ([]string, error) {
	list, err := stringList(p, "groups")
	if err != nil {
		return nil, err
	}
	for _, s := range list {
		if _, ok := getgrnam(groups, s); !ok {
			return nil, reject("Group not found: " + s)
		}
	}
	return list, nil
}
func expiry(value any) (int, error) {
	if value == nil {
		return -1, nil
	}
	s, ok := value.(string)
	if !ok {
		return 0, reject("Enter an account expiry date or leave it empty")
	}
	if s == "" {
		return -1, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil || t.Unix() <= 0 {
		return 0, reject("Invalid account expiry date")
	}
	return int(t.Unix() / 86400), nil
}
func isAdmin(u passwdUser, groups []groupEntry) bool {
	g, ok := getgrnam(groups, "sudo")
	return ok && (g.GID == u.GID || contains(g.Members, u.Name))
}
func protectAdmin(u passwdUser, actor string, loses bool, users []passwdUser, groups []groupEntry) error {
	if !loses {
		return nil
	}
	if u.Name == actor {
		return reject("You cannot remove your own panel access or administrator role")
	}
	db, err := readPolicy()
	if err != nil {
		return err
	}
	available := []string{}
	for _, row := range users {
		if !isAdmin(row, groups) || normal(users, row) != nil {
			continue
		}
		p := policyEntry(db, row)
		st, err := shadow(row.Name)
		if err != nil {
			return err
		}
		if !policyBool(p, "disabled", false) && policyBool(p, "panel", true) && st.PasswordStatus == "set" && !expired(st) && !passwordInactive(st.LastChange, st.MaxDays, st.InactiveDays) {
			available = append(available, row.Name)
		}
	}
	if contains(available, u.Name) && len(available) <= 1 {
		return reject("The last available administrator is protected")
	}
	return nil
}
func validateAccount(action string, p map[string]any, actor, target string, users []passwdUser, groups []groupEntry) ([]any, error) {
	details := []any{}
	primary := stringParam(p, "primaryGroup")
	if primary != "" {
		if _, ok := getgrnam(groups, primary); !ok {
			return nil, reject("Primary group not found")
		}
	}
	if action == "user.create" {
		if _, ok := getpwnam(users, target); ok {
			return nil, reject("User already exists")
		}
		path, err := newHome(p, target)
		if err != nil {
			return nil, err
		}
		if err := validateHome(path, target, false, users); err != nil {
			return nil, err
		}
		if err := displayName(p); err != nil {
			return nil, err
		}
		if _, err := selectedGroups(p, groups); err != nil {
			return nil, err
		}
		if primary == "" {
			if _, ok := getgrnam(groups, target); ok {
				return nil, reject("A group with this name exists; select a primary group")
			}
		}
		if err := password(p); err != nil {
			return nil, err
		}
		return []any{"Create Linux user and home folder with 0700 permissions", "SSH is disabled by default"}, nil
	}
	if action == "group.edit" {
		g, ok := getgrnam(groups, target)
		if !ok {
			return nil, reject("Group not found")
		}
		lo, hi, err := bounds("GID")
		if err != nil {
			return nil, err
		}
		if !(g.GID >= lo && g.GID <= hi) && target != "sudo" {
			return nil, reject("Service group is protected")
		}
		members, err := stringList(p, "members")
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			if _, err := account(users, m); err != nil {
				return nil, err
			}
		}
		for _, u := range users {
			if u.GID == g.GID && !contains(members, u.Name) {
				return nil, reject("Change the primary group before removing a primary member")
			}
		}
		if target == "sudo" {
			for _, old := range g.Members {
				if !contains(members, old) {
					u, err := account(users, old)
					if err != nil {
						return nil, err
					}
					if err := protectAdmin(u, actor, true, users, groups); err != nil {
						return nil, err
					}
				}
			}
			details = append(details, "Membership in sudo grants administrative privileges in Linux")
		}
		return details, nil
	}
	u, err := account(users, target)
	if err != nil {
		return nil, err
	}
	switch action {
	case "user.edit":
		if err := displayName(p); err != nil {
			return nil, err
		}
		list, err := selectedGroups(p, groups)
		if err != nil {
			return nil, err
		}
		gid := u.GID
		if primary != "" {
			g, _ := getgrnam(groups, primary)
			gid = g.GID
		}
		sudo, _ := getgrnam(groups, "sudo")
		if err := protectAdmin(u, actor, isAdmin(u, groups) && !contains(list, "sudo") && gid != sudo.GID, users, groups); err != nil {
			return nil, err
		}
	case "user.security":
		for _, k := range []string{"panel", "ssh", "disabled", "forcePasswordChange"} {
			if _, ok := p[k].(bool); !ok {
				return nil, reject("Access flags must be boolean")
			}
		}
		end, err := expiry(p["expiry"])
		if err != nil {
			return nil, err
		}
		if err := protectAdmin(u, actor, p["disabled"] == true || p["panel"] == false || (end >= 0 && end <= today()), users, groups); err != nil {
			return nil, err
		}
		if p["ssh"] == true {
			if !sshdInstalled() {
				return nil, reject("OpenSSH server is not installed")
			}
			list, err := shells()
			if err != nil {
				return nil, err
			}
			if !contains(list, stringParam(p, "shell")) {
				return nil, reject("Select an installed login shell")
			}
		}
		aging := map[string]int{}
		for _, k := range []string{"minDays", "maxDays", "warnDays", "inactiveDays"} {
			v, err := intParam(p, k, -1)
			if err != nil || v < -1 || v > 99999 {
				return nil, reject("Invalid password aging value")
			}
			aging[k] = v
		}
		st, err := shadow(target)
		if err != nil {
			return nil, err
		}
		last := st.LastChange
		if p["forcePasswordChange"] == true {
			last = 0
		}
		if err := protectAdmin(u, actor, passwordInactive(last, aging["maxDays"], aging["inactiveDays"]), users, groups); err != nil {
			return nil, err
		}
		if p["panel"] == true && p["disabled"] == false && st.PasswordStatus != "set" {
			return nil, reject("Set a Linux password before enabling panel access")
		}
		details = append(details, "Panel access and Linux account expiry are checked independently", "Disabling an account ends its panel and SSH sessions; active transfers may stop")
	case "user.identity":
		uid, err := intParam(p, "uid", -1)
		if err != nil {
			return nil, err
		}
		lo, hi, err := bounds("UID")
		if err != nil {
			return nil, err
		}
		if uid < lo || uid > hi || uid == 65534 {
			return nil, reject("UID is outside the Linux user range")
		}
		for _, row := range users {
			if row.UID == uid && row.Name != target {
				return nil, reject("UID is already in use")
			}
		}
		if err := protectAdmin(u, actor, true, users, groups); err != nil {
			return nil, err
		}
		if err := homeIdle(u); err != nil {
			return nil, err
		}
		details = append(details, "Only home-folder ownership is updated by usermod; files on other volumes retain their numeric owner")
	case "user.home":
		if err := validateHome(u.Dir, target, true, users); err != nil {
			return nil, err
		}
		path := stringParam(p, "home")
		if err := validateHome(path, target, false, users); err != nil {
			return nil, err
		}
		if err := homeIdle(u); err != nil {
			return nil, err
		}
		details = append(details, "Move "+u.Dir+" → "+path)
	case "user.password":
		if err := password(p); err != nil {
			return nil, err
		}
	case "user.delete":
		if actor == target {
			return nil, reject("You cannot delete yourself")
		}
		if err := protectAdmin(u, actor, true, users, groups); err != nil {
			return nil, err
		}
		if v, ok := p["deleteHome"]; ok {
			if _, ok := v.(bool); !ok {
				return nil, reject("deleteHome must be boolean")
			}
		}
		if p["deleteHome"] != false {
			if err := validateHome(u.Dir, target, true, users); err != nil {
				return nil, err
			}
			details = append(details, "DELETE HOME FOLDER: "+u.Dir)
		}
		if err := homeIdle(u); err != nil {
			return nil, err
		}
		details = append(details, "Files in shared folders will be preserved")
	}
	return details, nil
}
