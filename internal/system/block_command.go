package system

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// BlockDevicesCommand suppresses util-linux's root-only blkid fallback on
// releases predating --properties-by. Kernel and udev metadata remain readable;
// unavailable metadata must not cause an inventory request to wake a disk.
func BlockDevicesCommand(ctx context.Context, args ...string) (*exec.Cmd, error) {
	return blockDevicesCommand(ctx, os.Geteuid() == 0, user.Lookup, args...)
}

func blockDevicesCommand(ctx context.Context, root bool, lookup func(string) (*user.User, error), args ...string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/lsblk", args...)
	if !root {
		return cmd, nil
	}
	account, err := lookup("nobody")
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return nil, fmt.Errorf("unprivileged inventory account unavailable")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 {
		return nil, fmt.Errorf("unprivileged inventory group unavailable")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	return cmd, nil
}
