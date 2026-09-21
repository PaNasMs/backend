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
