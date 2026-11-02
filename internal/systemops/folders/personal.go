package folders

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"panasms.local/backend/internal/systemops"
)

type personalRequest struct {
	User   string `json:"user"`
	Target string `json:"target"`
}
type personalResponse struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

func PersonalQuery(ctx context.Context, name, target string) (json.RawMessage, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return nil, reject("Home folder is unavailable")
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	ids, err := account.GroupIds()
	if err != nil {
		return nil, err
	}
	groups := []uint32{}
	for _, value := range ids {
		id, e := strconv.ParseUint(value, 10, 32)
		if e != nil {
			return nil, e
		}
		groups = append(groups, uint32(id))
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	request, _ := json.Marshal(personalRequest{User: name, Target: target})
	cmd := exec.CommandContext(ctx, executable, "personal-folder-browser")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(request)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}}
	output, err := cmd.Output()
	if err != nil {
		return nil, reject("Home folder is unavailable")
	}
	var response personalResponse
	if err = systemops.Decode(output, &response); err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, reject(response.Error)
	}
	return response.Result, nil
}
func PersonalCommand(input io.Reader, output io.Writer) error {
	var request personalRequest
	if err := json.NewDecoder(io.LimitReader(input, 64*1024)).Decode(&request); err != nil {
		return err
	}
	result, err := personal(request.User, request.Target)
	response := personalResponse{Result: result}
	if err != nil {
		response.Error = err.Error()
	}
	return json.NewEncoder(output).Encode(response)
}
func personal(name, target string) (json.RawMessage, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return nil, reject("Home folder is unavailable")
	}
	return personalAccount(account, target)
}
func personalAccount(account *user.User, target string) (json.RawMessage, error) {
	if account.Uid != strconv.Itoa(os.Geteuid()) || account.Gid != strconv.Itoa(os.Getegid()) {
		return nil, reject("Access denied")
	}
	home, err := openDirectory(account.HomeDir)
	if err != nil {
		return nil, reject("Home folder is unavailable")
	}
	home.Close()
	response := listing{Roots: []folder{{Name: "Home", Path: account.HomeDir}}, Path: target, Folders: []folder{}}
	if target == "" {
		return json.Marshal(response)
	}
	if _, err = systemops.CleanPath(target); err != nil {
		return nil, err
	}
	if !within(target, account.HomeDir) {
		return nil, reject("Choose a folder inside your home without symbolic links")
	}
	dir, err := openDirectory(target)
	if err != nil {
		return nil, reject("Choose a folder inside your home without symbolic links")
	}
	defer dir.Close()
	response.Folders, err = children(dir, target, nil)
	if err != nil {
		return nil, fmt.Errorf("read home folder: %w", err)
	}
	return json.Marshal(response)
}
