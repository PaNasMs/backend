package auth

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Identity struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	UID      int    `json:"uid"`
	Role     string `json:"role"`
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
	if err != nil || uid == 0 {
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
	if !admin {
		return Identity{}, errors.New("prototype requires sudo membership")
	}
	return Identity{Username: username, Name: strings.Split(p[4], ",")[0], UID: uid, Role: "admin"}, nil
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
		return nil, errors.New("configure OSTOJAOS_AUTH_MODE=sudo or OSTOJAOS_ALLOWED_USERS")
	}
	return allowed, nil
}
