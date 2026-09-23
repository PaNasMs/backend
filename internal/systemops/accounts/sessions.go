package accounts

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops"
)

// session is one SSH login session, mirroring the dict account_sessions.sessions
// builds. Only sshd-service sessions for the target user are reported.
type session struct {
	ID      string `json:"id"`
	User    string `json:"user"`
	UID     string `json:"uid"`
	Address string `json:"address"`
	Leader  string `json:"leader"`
	State   string `json:"state"`
	Created string `json:"created"`
	Kind    string `json:"kind"`
}

// listSessions reproduces account_sessions.sessions(username): it lists login
// sessions, keeps those whose third column is the target user, then queries each
// session's properties and retains only sshd/sshd-session services for that
// exact user. A per-session query failure skips that session, as in Python.
func listSessions(ctx context.Context, username string) ([]session, error) {
	out, err := systemops.Command(ctx, []string{"loginctl", "list-sessions", "--no-legend", "--no-pager"}, systemops.CommandOptions{Accepted: []int{0, 1}, Timeout: 10 * time.Second})
	if err != nil {
		return nil, err
	}
	result := []session{}
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[2] != username {
			continue
		}
		raw, err := systemops.Command(ctx, []string{"loginctl", "show-session", fields[0], "-p", "Name", "-p", "User", "-p", "Service", "-p", "RemoteHost", "-p", "Leader", "-p", "State", "-p", "Timestamp"}, systemops.CommandOptions{Timeout: 5 * time.Second})
		if err != nil {
			continue
		}
		values := map[string]string{}
		for _, kv := range strings.Split(string(raw), "\n") {
			if i := strings.Index(kv, "="); i >= 0 {
				values[kv[:i]] = kv[i+1:]
			}
		}
		if values["Name"] != username {
			continue
		}
		if values["Service"] != "sshd" && values["Service"] != "sshd-session" {
			continue
		}
		result = append(result, session{
			ID:      fields[0],
			User:    username,
			UID:     values["User"],
			Address: values["RemoteHost"],
			Leader:  values["Leader"],
			State:   values["State"],
			Created: values["Timestamp"],
			Kind:    "ssh",
		})
	}
	return result, nil
}

// Sessions serves the account-sessions view.
func Sessions(ctx context.Context, username string) (json.RawMessage, error) {
	sessions, err := listSessions(ctx, username)
	if err != nil {
		return nil, err
	}
	return marshal(sessions)
}

// terminate reproduces account_sessions.terminate(): it ends the selected
// sessions (all of the user's, or one by id) and then requires that none remain
// in a non-closing state, matching the Python post-check.
func terminate(ctx context.Context, username, sessionID string) error {
	all, err := listSessions(ctx, username)
	if err != nil {
		return err
	}
	selected := []session{}
	for _, s := range all {
		if sessionID == "" || s.ID == sessionID {
			selected = append(selected, s)
		}
	}
	if sessionID != "" && len(selected) == 0 {
		return &systemops.Rejected{Message: "SSH session has already ended"}
	}
	for _, s := range selected {
		if _, err := systemops.Command(ctx, []string{"loginctl", "terminate-session", s.ID}, systemops.CommandOptions{Operation: true}); err != nil {
			return err
		}
	}
	selectedIDs := map[string]bool{}
	for _, s := range selected {
		selectedIDs[s.ID] = true
	}
	remaining, err := listSessions(ctx, username)
	if err != nil {
		return err
	}
	for _, s := range remaining {
		if selectedIDs[s.ID] && s.State != "closing" {
			return &systemops.Rejected{Message: "Some SSH sessions could not be ended; account access restrictions are already applied"}
		}
	}
	return nil
}
