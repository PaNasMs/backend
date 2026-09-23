package accounts

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthorizedKeysRejectsFIFOWithoutBlocking(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(home, ".ssh", "authorized_keys"), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ManageKeys(home, KeyRequest{Action: "list"}); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked opening FIFO")
	}
}

func TestFractionalPolicyUIDDoesNotMatchAccount(t *testing.T) {
	db := policyDB{"alice": {"uid": 1001.5, "panel": true}}
	if len(policyEntry(db, passwdUser{Name: "alice", UID: 1001})) != 0 {
		t.Fatal("fractional UID inherited account policy")
	}
}

func TestLocalIdentityRequiresMatchingNameAndUID(t *testing.T) {
	users := []passwdUser{{Name: "alice", UID: 1000}, {Name: "bob", UID: 1001}}
	if !isLocal(users, users[0]) {
		t.Fatal("local account rejected")
	}
	for _, u := range []passwdUser{{Name: "remote", UID: 1000}, {Name: "alice", UID: 1001}, {Name: "alice", UID: 2000}} {
		if isLocal(users, u) {
			t.Fatalf("ambiguous NSS identity accepted: %+v", u)
		}
	}
	users = append(users, passwdUser{Name: "duplicate", UID: 1000})
	if isLocal(users, users[0]) {
		t.Fatal("duplicate UID accepted")
	}
}
func TestExitedProcessesDoNotHoldHomeFiles(t *testing.T) {
	for _, state := range []string{"Z (zombie)", "X (dead)"} {
		if !exitedProcess("Name:\ttest\nState:\t" + state + "\n") {
			t.Fatal(state)
		}
	}
	if exitedProcess("State:\tS (sleeping)\n") {
		t.Fatal("live process ignored")
	}
}
