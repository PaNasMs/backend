package accounts

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"

	"panasms.local/backend/internal/systemops"
)

// keyOperation runs the isolated key writer for target, matching
// accounts.key_operation(): it invokes the privilege-dropping helper with the
// JSON body and returns the parsed key list.
func keyOperation(ctx context.Context, target string, req KeyRequest) ([]Key, error) {
	data, err := marshalRaw(req)
	if err != nil {
		return nil, err
	}
	out, err := systemops.Command(ctx, []string{keysHelper, target}, systemops.CommandOptions{Input: data})
	if err != nil {
		return nil, err
	}
	var keys []Key
	if err := systemops.Decode(out, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// keysHelper is the path to the isolated key-writer binary (the Go port of
// profile-keys.py). It is overridable in tests.
var keysHelper = "/usr/lib/panasms/panasms-keys"

func applySSH(ctx context.Context) error {
	if !sshdInstalled() {
		return nil
	}
	const path = "/etc/ssh/sshd_config.d/60-panasms-users.conf"
	db, err := readPolicy()
	if err != nil {
		return err
	}
	denied := []string{}
	for name, p := range db {
		if policyBool(p, "disabled", false) || !policyBool(p, "ssh", true) {
			if _, err := systemops.Name(name); err != nil {
				return err
			}
			denied = append(denied, name)
		}
	}
	sort.Strings(denied)
	previous, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	text := "# Managed by PaNasMs.\n"
	if len(denied) > 0 {
		text += "DenyUsers " + strings.Join(denied, " ") + "\n"
	}
	if err := systemops.AtomicWrite(path, text, 0644); err != nil {
		return err
	}
	validate := func() error {
		if _, err := systemops.Command(ctx, []string{"sshd", "-t"}, systemops.CommandOptions{}); err != nil {
			return err
		}
		for _, user := range denied {
			raw, err := systemops.Command(ctx, []string{"sshd", "-T", "-C", "user=" + user + ",host=localhost,addr=127.0.0.1"}, systemops.CommandOptions{})
			if err != nil {
				return err
			}
			found := false
			for _, line := range strings.Split(string(raw), "\n") {
				fields := strings.Fields(line)
				if len(fields) > 1 && fields[0] == "denyusers" && contains(fields[1:], user) {
					found = true
				}
			}
			if !found {
				return reject("OpenSSH did not apply the account access policy")
			}
		}
		_, err := systemops.Command(ctx, []string{"systemctl", "reload", "ssh.service"}, systemops.CommandOptions{Operation: true, Accepted: []int{0, 5}})
		return err
	}
	if err := validate(); err != nil {
		if os.IsNotExist(readErr) {
			return errors.Join(err, os.Remove(path))
		}
		return errors.Join(err, systemops.AtomicWrite(path, string(previous), 0644))
	}
	return nil
}
