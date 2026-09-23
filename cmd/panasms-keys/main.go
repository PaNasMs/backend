package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/accounts"
)

func fail() { fmt.Fprintln(os.Stderr, "SSH key operation failed"); os.Exit(1) }

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--home-worker" {
		if deleteHomeContents() != nil {
			fail()
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "--delete-home" {
		if deleteHome(os.Args[2]) != nil {
			fail()
		}
		return
	}

	if len(os.Args) == 3 && os.Args[1] == "--worker" {
		if os.Geteuid() == 0 || os.Getuid() == 0 {
			fail()
		}
		data, err := io.ReadAll(io.LimitReader(os.Stdin, systemops.MaxInput+1))
		if err != nil || len(data) > systemops.MaxInput {
			fail()
		}
		var req accounts.KeyRequest
		if systemops.Decode(data, &req) != nil {
			fail()
		}
		keys, err := accounts.ManageKeys(os.Args[2], req)
		if err != nil || json.NewEncoder(os.Stdout).Encode(keys) != nil {
			fail()
		}
		return
	}
	if len(os.Args) != 2 || os.Geteuid() != 0 {
		fail()
	}
	u, err := user.Lookup(os.Args[1])
	if err != nil {
		fail()
	}
	credentials, err := credentialsFor(u)
	if err != nil {
		fail()
	}
	executable, err := os.Executable()
	if err != nil {
		fail()
	}
	// Set credentials in fork/exec, before the worker starts its Go runtime.
	cmd := exec.Command(executable, "--worker", u.HomeDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credentials}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "HOME=" + u.HomeDir}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, systemops.MaxInput+1))
	if err != nil || len(data) > systemops.MaxInput {
		fail()
	}
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if cmd.Run() != nil {
		fail()
	}
}

func credentialsFor(u *user.User) (*syscall.Credential, error) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil || uid == 0 {
		return nil, fmt.Errorf("invalid uid")
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	c := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}
	for _, id := range ids {
		n, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return nil, err
		}
		if n != gid {
			c.Groups = append(c.Groups, uint32(n))
		}
	}
	return c, nil
}
