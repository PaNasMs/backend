package system

import (
	"context"
	"errors"
	"os/user"
	"testing"
)

func TestRootBlockInventoryDropsDeviceReadPrivileges(t *testing.T) {
	cmd, err := blockDevicesCommand(context.Background(), true, func(name string) (*user.User, error) {
		if name != "nobody" {
			t.Fatal(name)
		}
		return &user.User{Uid: "65534", Gid: "65534"}, nil
	}, "--json")
	if err != nil {
		t.Fatal(err)
	}
	cred := cmd.SysProcAttr.Credential
	if cmd.Path != "/usr/bin/lsblk" || cred.Uid != 65534 || cred.Gid != 65534 || cred.NoSetGroups || len(cred.Groups) != 0 {
		t.Fatalf("unsafe inventory command %+v", cmd)
	}
	if len(cmd.SysProcAttr.AmbientCaps) != 0 {
		t.Fatal("ambient privileges retained")
	}
	for _, account := range []*user.User{{Uid: "0", Gid: "65534"}, {Uid: "65534", Gid: "0"}, {Uid: "bad", Gid: "65534"}} {
		if _, err := blockDevicesCommand(context.Background(), true, func(string) (*user.User, error) { return account, nil }); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	if _, err := blockDevicesCommand(context.Background(), true, func(string) (*user.User, error) { return nil, errors.New("missing") }); err == nil {
		t.Fatal("missing identity allowed")
	}
}

func TestUnprivilegedInventoryDoesNotRequestCredentialChange(t *testing.T) {
	cmd, err := blockDevicesCommand(context.Background(), false, func(string) (*user.User, error) { t.Fatal("unneeded account lookup"); return nil, nil })
	if err != nil || cmd.SysProcAttr != nil {
		t.Fatalf("%v %v", cmd, err)
	}
}
