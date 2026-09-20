package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"os/user"
	"strings"
	"time"
	"unicode"
)

type Key struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
}
type Profile struct {
	Username string   `json:"username"`
	Name     string   `json:"name"`
	UID      string   `json:"uid"`
	Home     string   `json:"home"`
	Groups   []string `json:"groups"`
	Keys     []Key    `json:"keys"`
}

func Keys(ctx context.Context, username string, body any) ([]Key, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "/usr/lib/panasms/profile-keys.py", username)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.New("SSH key operation failed")
	}
	var keys []Key
	err = json.Unmarshal(out, &keys)
	return keys, err
}
func Read(ctx context.Context, username string) (Profile, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return Profile{}, err
	}
	groups, err := exec.CommandContext(ctx, "/usr/bin/id", "-nG", username).Output()
	if err != nil {
		return Profile{}, err
	}
	keys, err := Keys(ctx, username, map[string]string{"action": "list"})
	if err != nil {
		return Profile{}, err
	}
	return Profile{username, strings.Split(u.Name, ",")[0], u.Uid, u.HomeDir, strings.Fields(string(groups)), keys}, nil
}
func ValidName(name string) bool {
	if len([]rune(name)) > 80 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || strings.ContainsRune(":,", r) {
			return false
		}
	}
	return true
}
func SetName(ctx context.Context, username, name string) error {
	if !ValidName(name) {
		return errors.New("invalid name")
	}
	return exec.CommandContext(ctx, "/usr/sbin/usermod", "--comment", name, "--", username).Run()
}
