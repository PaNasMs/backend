package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"time"
)

func Password(ctx context.Context, user, current, next string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, _ := json.Marshal(map[string]string{"user": user, "current": current, "next": next})
	cmd := exec.CommandContext(ctx, "/usr/lib/panasms/panasms-password")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.Stdin = bytes.NewReader(raw)
	out, err := cmd.Output()
	if err != nil {
		return errors.New("Password helper unavailable")
	}
	var result struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(out, &result) != nil {
		return errors.New("Invalid password helper response")
	}
	if result.Error != "" {
		return errors.New(result.Error)
	}
	return nil
}

func SyncSMB(ctx context.Context, user, password string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	raw, _ := json.Marshal(map[string]string{"user": user, "password": password})
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "/usr/lib/panasms/management/sharing.py", "--sync")
	cmd.Stdin = bytes.NewReader(raw)
	if err := cmd.Run(); err != nil {
		return errors.New("Linux password accepted, but SMB synchronization failed. See Shared folders / Accounts; sign in again to retry.")
	}
	return nil
}
