package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Identity struct {
	SMBSyncWarning bool   `json:"smbSyncWarning,omitempty"`
	Username       string `json:"username"`
	Name           string `json:"name"`
	UID            int    `json:"uid"`
	Role           string `json:"role"`
	Epoch          string `json:"epoch"`
	Principal      string `json:"principal"`
	Created        string `json:"created"`
}

func Lookup(username string, allowed map[string]bool) (Identity, error) {
	if (allowed != nil && !allowed[username]) || username == "" || strings.HasPrefix(username, "-") {
		return Identity{}, errors.New("access denied")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "/usr/bin/getent", "passwd", username).Output()
	if err != nil {
		return Identity{}, err
	}
	p := strings.Split(strings.TrimSpace(string(raw)), ":")
	if len(p) != 7 || p[0] != username {
		return Identity{}, errors.New("unknown user")
	}
	uid, err := strconv.Atoi(p[2])
	if err != nil || !NormalAccount(username, uid) {
		return Identity{}, errors.New("protected account")
	}
	groups, err := exec.CommandContext(ctx, "/usr/bin/id", "-nG", username).Output()
	if err != nil {
		return Identity{}, err
	}
	admin := false
	for _, g := range strings.Fields(string(groups)) {
		if g == "sudo" {
			admin = true
		}
	}
	policy, err := AccountPolicy(username, uid)
	if err != nil || policy.Disabled || (policy.Panel != nil && !*policy.Panel) || (!admin && policy.Panel == nil) {
		return Identity{}, errors.New("panel access denied")
	}
	role := "user"
	if admin {
		role = "admin"
	}
	return Identity{Username: username, Name: strings.Split(p[4], ",")[0], UID: uid, Role: role, Epoch: policy.Epoch, Principal: policy.Principal, Created: policy.Created}, nil
}

func AccessPolicy(mode, users string) (map[string]bool, error) {
	if mode == "sudo" {
		return nil, nil
	}
	if mode != "" && mode != "allowlist" {
		return nil, errors.New("unknown authentication mode")
	}
	allowed := map[string]bool{}
	for _, user := range strings.Split(users, ",") {
		if user = strings.TrimSpace(user); user != "" {
			allowed[user] = true
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("configure PANASMS_AUTH_MODE=sudo or PANASMS_ALLOWED_USERS")
	}
	return allowed, nil
}

type Policy struct {
	UID       int    `json:"uid"`
	Panel     *bool  `json:"panel"`
	Disabled  bool   `json:"disabled"`
	Epoch     string `json:"epoch"`
	Principal string `json:"principal"`
	Created   string `json:"created"`
}

func AccountPolicy(username string, uid int) (Policy, error) {
	raw, err := os.ReadFile("/etc/panasms/accounts.json")
	if os.IsNotExist(err) {
		return Policy{}, nil
	}
	if err != nil {
		return Policy{}, err
	}
	var entries map[string]Policy
	if err = json.Unmarshal(raw, &entries); err != nil {
		return Policy{}, err
	}
	p, exists := entries[username]
	if exists && p.UID != uid {
		return Policy{}, errors.New("account identity changed; review access")
	}
	return p, nil
}
func NormalAccount(username string, uid int) bool {
	if uid == 0 || uid == 65534 || username == "panasms" {
		return false
	}
	lo, hi := 1000, 60000
	if raw, err := os.ReadFile("/etc/login.defs"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			v, err := strconv.Atoi(f[1])
			if err != nil {
				continue
			}
			if f[0] == "UID_MIN" {
				lo = v
			}
			if f[0] == "UID_MAX" {
				hi = v
			}
		}
	}
	if uid < lo || uid > hi {
		return false
	}
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false
	}
	found, matching := false, 0
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		if fields[2] == strconv.Itoa(uid) {
			matching++
			if fields[0] == username {
				found = true
			}
		}
	}
	return found && matching == 1
}
