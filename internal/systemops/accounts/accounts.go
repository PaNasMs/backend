// Package accounts manages Linux accounts through native tools and host policy.
package accounts

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"panasms.local/backend/internal/systemops"
)

func reject(msg string) error { return &systemops.Rejected{Message: msg} }

func marshal(v any) (json.RawMessage, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

func marshalRaw(v any) ([]byte, error) { return json.Marshal(v) }

// bounds reads UID_MIN/UID_MAX (or GID_*) from /etc/login.defs, defaulting to
// 1000..60000, matching accounts.bounds().
func bounds(kind string) (int, int, error) {
	lo, hi := 1000, 60000
	raw, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) <= 1 {
			continue
		}
		n, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		switch f[0] {
		case kind + "_MIN":
			lo = n
		case kind + "_MAX":
			hi = n
		}
	}
	return lo, hi, nil
}

// isLocal reproduces accounts.local(): the user's uid appears in exactly one
// /etc/passwd row with the same name (not an NSS-only or ambiguous entry).
func isLocal(users []passwdUser, u passwdUser) bool {
	count := 0
	nameSeen := false
	for _, row := range users {
		if row.UID == u.UID {
			count++
		}
		if row.Name == u.Name && row.UID == u.UID {
			nameSeen = true
		}
	}
	return count == 1 && nameSeen
}

// normal reproduces accounts.normal(): rejects service/system accounts. The
// account must be within the UID range, not nobody (65534), not "panasms", and
// a genuine local account.
func normal(users []passwdUser, u passwdUser) error {
	lo, hi, err := bounds("UID")
	if err != nil {
		return err
	}
	local, err := localUsers()
	if err != nil {
		return err
	}
	if !(lo <= u.UID && u.UID <= hi && u.UID != 65534 && u.Name != "panasms" && isLocal(local, u)) {
		return reject("Service account is protected")
	}
	return nil
}

// account validates a username and returns its normal (non-service) passwd
// record, matching accounts.account().
func account(users []passwdUser, value string) (passwdUser, error) {
	if _, err := systemops.Name(value); err != nil {
		return passwdUser{}, err
	}
	u, ok := getpwnam(users, value)
	if !ok {
		return passwdUser{}, reject("User not found")
	}
	if err := normal(users, u); err != nil {
		return passwdUser{}, err
	}
	return u, nil
}

// shells reproduces accounts.shells(): the login shells from /etc/shells that
// exist as files and are not nologin/false.
func shells() ([]string, error) {
	raw, err := os.ReadFile("/etc/shells")
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		if !strings.HasPrefix(s, "/") {
			continue
		}
		if strings.HasSuffix(s, "nologin") || strings.HasSuffix(s, "false") {
			continue
		}
		if info, err := os.Stat(s); err == nil && info.Mode().IsRegular() {
			out = append(out, s)
		}
	}
	return out, nil
}

func inShells(list []string, shell string) bool {
	for _, s := range list {
		if s == shell {
			return true
		}
	}
	return false
}

// policyBool returns a boolean policy flag, defaulting to def when absent.
func policyBool(policy map[string]any, key string, def bool) bool {
	if v, ok := policy[key].(bool); ok {
		return v
	}
	return def
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}
