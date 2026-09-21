package main

import (
	"encoding/json"
	"io"
	"os"
	"os/user"
	"panasms.local/backend/internal/auth"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	var body struct {
		User    string `json:"user"`
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	output := map[string]string{}
	defer func() { json.NewEncoder(os.Stdout).Encode(output) }()
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 24000))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF || body.Current == "" || body.Next == "" || len(body.Current) > 4096 || len(body.Next) > 4096 || strings.ContainsAny(body.Current+body.Next, "\x00\r\n") {
		output["error"] = "Invalid password input"
		return
	}
	account, err := user.Lookup(body.User)
	if err != nil {
		output["error"] = "User not found"
		return
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || !auth.NormalAccount(body.User, uid) {
		output["error"] = "Service account is protected"
		return
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		output["error"] = "Invalid account group"
		return
	}
	groups, err := account.GroupIds()
	if err != nil {
		output["error"] = "Account groups unavailable"
		return
	}
	gids := make([]int, 0, len(groups))
	for _, group := range groups {
		v, err := strconv.Atoi(group)
		if err != nil {
			output["error"] = "Invalid account group"
			return
		}
		gids = append(gids, v)
	}
	runtime.LockOSThread()
	if syscall.Setgroups(gids) != nil || syscall.Setresgid(gid, gid, gid) != nil {
		output["error"] = "Password helper unavailable"
		return
	}
	// Match passwd's real-user/effective-root identity so PAM enforces user policy.
	if err := syscall.Setresuid(uid, 0, 0); err != nil {
		output["error"] = "Password helper unavailable"
		return
	}
	if err := auth.ChangePassword(body.User, body.Current, body.Next); err != nil {
		output["error"] = err.Error()
	}
}
