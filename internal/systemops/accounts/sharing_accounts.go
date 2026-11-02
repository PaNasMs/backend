package accounts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops"
)

func sharingPasswordRevision(username string) (string, error) {
	raw, err := readFile("/etc/shadow")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 1 && fields[0] == username {
			sum := sha256.Sum256([]byte(fields[1]))
			return hex.EncodeToString(sum[:]), nil
		}
	}
	return "", nil
}
func readSharingCredentials(username string) (sharingCredentials, error) {
	var result sharingCredentials
	users, err := getpwall()
	if err != nil {
		return result, err
	}
	u, ok := getpwnam(users, username)
	if !ok {
		return result, reject("User not found")
	}
	result.UID = u.UID
	db, err := readPolicy()
	if err != nil {
		return result, err
	}
	result.Disabled = policyBool(policyEntry(db, u), "disabled", false)
	result.Shadow, err = shadow(username)
	if err != nil {
		return result, err
	}
	result.Revision, err = sharingPasswordRevision(username)
	return result, err
}
func (s *sharingService) accountStatus(username string) (json.RawMessage, error) {
	st, err := s.read()
	if err != nil {
		return nil, err
	}
	u, err := s.user(username)
	if err != nil {
		return nil, err
	}
	record := st.Accounts[username]
	if record == nil || record.UID == nil || *record.UID != u.UID {
		return marshal(map[string]any{"enabled": false, "status": "disabled"})
	}
	status := record.Status
	if status == "" {
		status = "pending"
	}
	if record.Enabled && status == "ready" {
		revision, err := s.revision(username)
		if err != nil {
			return nil, err
		}
		if record.PasswordRevision != revision {
			status = "pending"
		}
	}
	return marshal(map[string]any{"enabled": record.Enabled, "status": status})
}
func (s *sharingService) disconnect(ctx context.Context, username string, r *systemops.Reporter) error {
	if !s.tool("smbstatus") {
		return nil
	}
	state, err := s.run(ctx, []string{"systemctl", "is-active", "smbd"}, systemops.CommandOptions{Accepted: []int{0, 3, 4}})
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(state)) != "active" {
		return nil
	}
	var sessions struct {
		Sessions map[string]struct {
			Username string `json:"username"`
			ServerID struct {
				PID json.Number `json:"pid"`
			} `json:"server_id"`
		} `json:"sessions"`
	}
	raw, err := s.run(ctx, []string{"smbstatus", "--json"}, systemops.CommandOptions{Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	if err = systemops.Decode(raw, &sessions); err != nil {
		return err
	}
	main, err := s.command(ctx, []string{"systemctl", "show", "--property=MainPID", "--value", "smbd"}, false, nil)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, session := range sessions.Sessions {
		pid := session.ServerID.PID.String()
		value, e := session.ServerID.PID.Int64()
		if session.Username != username || e != nil || value <= 1 || pid == main || seen[pid] {
			continue
		}
		seen[pid] = true
		if _, err = s.run(ctx, []string{"smbcontrol", pid, "shutdown"}, systemops.CommandOptions{Accepted: []int{0, 1}, Operation: true, Reporter: r}); err != nil {
			return err
		}
	}
	return nil
}
func (s *sharingService) disable(ctx context.Context, username string, r *systemops.Reporter) error {
	if !s.tool("smbpasswd") {
		return nil
	}
	if _, err := s.run(ctx, []string{"smbpasswd", "-d", username}, systemops.CommandOptions{Accepted: []int{0, 1}, Operation: true, Reporter: r}); err != nil {
		return err
	}
	return s.disconnect(ctx, username, r)
}
func (s *sharingService) syncPassword(ctx context.Context, username, password string) error {
	st, err := s.read()
	if err != nil {
		return err
	}
	record := st.Accounts[username]
	u, err := s.user(username)
	if err != nil {
		return err
	}
	if record == nil || !record.Enabled || record.UID == nil || *record.UID != u.UID {
		return nil
	}
	sync := func() error {
		if password == "" || strings.ContainsAny(password, "\x00\r\n") {
			return reject("Invalid password")
		}
		credentials, err := s.credentials(username)
		if err != nil {
			return err
		}
		if credentials.Disabled || expired(credentials.Shadow) {
			return reject("Account is disabled")
		}
		if _, err = s.run(ctx, []string{"smbpasswd", "-s", "-a", username}, systemops.CommandOptions{Input: []byte(password + "\n" + password + "\n"), Operation: true}); err != nil {
			return err
		}
		if _, err = s.run(ctx, []string{"smbpasswd", "-e", username}, systemops.CommandOptions{Operation: true}); err != nil {
			return err
		}
		record.Status = "ready"
		record.PasswordRevision, err = s.revision(username)
		return err
	}
	if err = sync(); err != nil {
		record.Status = "error"
		_ = s.disable(context.WithoutCancel(ctx), username, nil)
		if err = s.save(st); err != nil {
			return err
		}
		return reject("Linux password accepted, but SMB password synchronization failed. See Users → Security and retry by signing in again.")
	}
	return s.save(st)
}
func (s *sharingService) reconcile(ctx context.Context) error {
	st, err := s.read()
	if err != nil {
		return err
	}
	changed := false
	var failures error
	for username, record := range st.Accounts {
		if !record.Enabled {
			continue
		}
		credentials, e := s.credentials(username)
		available := e == nil && record.UID != nil && credentials.UID == *record.UID && !credentials.Disabled && credentials.Shadow.PasswordStatus == "set" && !expired(credentials.Shadow) && !passwordInactive(credentials.Shadow.LastChange, credentials.Shadow.MaxDays, credentials.Shadow.InactiveDays)
		status := "disabled"
		if available {
			status = record.Status
			if status == "" || credentials.Revision != record.PasswordRevision {
				status = "pending"
			}
		}
		if status != record.Status || record.Status == "error" {
			if err = s.disable(ctx, username, nil); err != nil {
				failures = errors.Join(failures, err)
				continue
			}
			if status != record.Status {
				record.Status = status
				changed = true
			}
		}
	}
	if changed {
		failures = errors.Join(failures, s.save(st))
	}
	return failures
}
func (s *sharingService) dependency(ctx context.Context, operation, username, password string) (json.RawMessage, error) {
	if !homeAccountName(username) {
		return nil, reject("Invalid name")
	}
	if operation == "status" {
		return s.accountStatus(username)
	}
	unlock, err := s.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	switch operation {
	case "sync-password":
		err = s.syncPassword(ctx, username, password)
	case "disable":
		err = s.disable(ctx, username, nil)
	case "disconnect":
		err = s.disconnect(ctx, username, nil)
	case "remove":
		st, e := s.read()
		if e != nil {
			return nil, e
		}
		if st.Accounts[username] == nil {
			break
		}
		if err = s.disable(ctx, username, nil); err != nil {
			return nil, err
		}
		if _, err = s.run(ctx, []string{"smbpasswd", "-x", username}, systemops.CommandOptions{Accepted: []int{0, 1}, Operation: true}); err != nil {
			return nil, err
		}
		delete(st.Accounts, username)
		err = s.save(st)
	default:
		return nil, reject("Unknown account dependency operation")
	}
	if err != nil {
		return nil, err
	}
	return marshal(map[string]any{})
}
