package accounts

import (
	"encoding/json"
	"os"
	"panasms.local/backend/internal/systemops"
	"strconv"
	"strings"
	"time"
)

// policyPath is the PaNasMs per-account policy file, mirroring
// account_policy.PATH.
const policyPath = "/etc/panasms/accounts.json"

// policyDB is the parsed accounts.json: username → arbitrary policy record. The
// records are open maps because the panel stores several optional flags
// (panel, ssh, disabled, expiry, principal, created, epoch, uid).
type policyDB map[string]map[string]any

// readPolicy loads accounts.json, returning an empty db when the file is
// absent, matching account_policy.read().
func readPolicy() (policyDB, error) {
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return policyDB{}, nil
		}
		return nil, err
	}
	db := policyDB{}
	if err := systemops.Decode(raw, &db); err != nil {
		return nil, err
	}
	if db == nil {
		return nil, reject("Invalid account policy configuration")
	}
	return db, nil
}

// policyEntry returns the policy record for a user only when its stored uid
// matches the account's current uid, matching account_policy.entry(): a record
// left behind by a deleted-and-recreated name must not apply to the new account.
func policyEntry(db policyDB, u passwdUser) map[string]any {
	record := db[u.Name]
	if record == nil {
		return map[string]any{}
	}
	var matches bool
	switch stored := record["uid"].(type) {
	case json.Number:
		uid, err := stored.Int64()
		matches = err == nil && uid == int64(u.UID)
	case float64:
		matches = stored == float64(u.UID)
	}
	if !matches {
		return map[string]any{}
	}
	return record
}

// ShadowState is the parsed /etc/shadow view of one account, mirroring
// account_policy.shadow(). Numeric fields are -1 when the shadow field is empty.
type ShadowState struct {
	PasswordStatus      string `json:"passwordStatus"`
	LastChange          int    `json:"lastChange"`
	MinDays             int    `json:"minDays"`
	MaxDays             int    `json:"maxDays"`
	WarnDays            int    `json:"warnDays"`
	InactiveDays        int    `json:"inactiveDays"`
	ExpiryDay           int    `json:"expiryDay"`
	ForcePasswordChange bool   `json:"forcePasswordChange"`
}

// shadow parses /etc/shadow for username, matching account_policy.shadow().
// An unknown user yields the "unknown" status with all other fields -1/false.
func shadow(username string) (ShadowState, error) {
	raw, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return ShadowState{}, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if fields[0] != username {
			continue
		}
		for len(fields) < 9 {
			fields = append(fields, "")
		}
		num := func(i int) int {
			if fields[i] == "" {
				return -1
			}
			n, err := strconv.Atoi(fields[i])
			if err != nil {
				return -1
			}
			return n
		}
		status := "set"
		switch {
		case fields[1] == "":
			status = "empty"
		case strings.HasPrefix(fields[1], "!") || strings.HasPrefix(fields[1], "*"):
			status = "locked"
		}
		last := num(2)
		return ShadowState{
			PasswordStatus:      status,
			LastChange:          last,
			MinDays:             num(3),
			MaxDays:             num(4),
			WarnDays:            num(5),
			InactiveDays:        num(6),
			ExpiryDay:           num(7),
			ForcePasswordChange: last == 0,
		}, nil
	}
	return ShadowState{PasswordStatus: "unknown", LastChange: -1, MinDays: -1, MaxDays: -1, WarnDays: -1, InactiveDays: -1, ExpiryDay: -1}, nil
}

// today is the number of days since the Unix epoch, matching Python's
// (date.today() - date(1970,1,1)).days used throughout account_policy.
func today() int {
	year, month, day := time.Now().Date()
	return int(time.Date(year, month, day, 0, 0, 0, 0, time.UTC).Unix() / 86400)
}

// expired reports whether the account's password/expiry day has passed,
// matching account_policy.expired().
func expired(s ShadowState) bool {
	return s.ExpiryDay >= 0 && s.ExpiryDay <= today()
}

// passwordInactive reproduces account_policy.password_inactive(): a set password
// is inactive once today is past lastChange + maxDays + inactiveDays, but only
// when all three are meaningfully set.
func passwordInactive(last, maximum, inactive int) bool {
	return last > 0 && maximum >= 0 && inactive >= 0 && today() > last+maximum+inactive
}

func savePolicy(u passwdUser, changes map[string]any, revoke bool) error {
	db, err := readPolicy()
	if err != nil {
		return err
	}
	record := policyEntry(db, u)
	for k, v := range changes {
		record[k] = v
	}
	record["uid"] = u.UID
	if revoke {
		record["epoch"] = randomID()
	}
	db[u.Name] = record
	raw, err := json.Marshal(db)
	if err != nil {
		return err
	}
	return systemops.AtomicWrite(policyPath, string(raw), 0644)
}
