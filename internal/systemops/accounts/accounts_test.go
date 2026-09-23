package accounts

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A real ed25519 public key with the id/type/fingerprint/comment computed by the
// Python profile-keys.py key_info() (and cross-checked against `ssh-keygen -l`),
// so KeyInfo parity is anchored to an authoritative vector rather than to itself.
const (
	testKey     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFZSSHyKh+uAI7dPrViDxLydPgDx/cBLms+NhtH0/SqL test@example"
	testKeyID   = "f61c5537ce79276d13df8985605d8c238f965fd108f2309cd62781c31ce9a670"
	testKeyType = "ssh-ed25519"
	testKeyFP   = "SHA256:G6NrzVBRQ2UDZnp38Eu3O+INBNmexVO5LJPiEJF27xA"
)

func TestKeyInfoMatchesPython(t *testing.T) {
	k, ok := KeyInfo(testKey)
	if !ok {
		t.Fatal("KeyInfo rejected a valid key")
	}
	if k.ID != testKeyID {
		t.Errorf("id: got %s want %s", k.ID, testKeyID)
	}
	if k.Type != testKeyType {
		t.Errorf("type: got %s want %s", k.Type, testKeyType)
	}
	if k.Fingerprint != testKeyFP {
		t.Errorf("fingerprint: got %s want %s", k.Fingerprint, testKeyFP)
	}
	if k.Comment != "test@example" {
		t.Errorf("comment: got %q want %q", k.Comment, "test@example")
	}
}

func TestKeyInfoRejectsNonKeys(t *testing.T) {
	for _, line := range []string{"", "# a comment", "not-a-key blob", "ssh-ed25519"} {
		if _, ok := KeyInfo(line); ok {
			t.Errorf("KeyInfo accepted a non-key line %q", line)
		}
	}
}

func TestKeyInfoWithOptionsFindsKeyToken(t *testing.T) {
	// key_info scans for the first ssh-/ecdsa-/sk- token, so a line carrying
	// options still parses (only the add path rejects options).
	line := `no-pty,command="x" ` + testKey
	k, ok := KeyInfo(line)
	if !ok {
		t.Fatal("KeyInfo should find the key token past options")
	}
	if k.Type != testKeyType || k.Comment != "test@example" {
		t.Errorf("unexpected parse: %+v", k)
	}
}

func TestParseKeysPreservesOrderAndSkipsBlanks(t *testing.T) {
	keys := parseKeys([]string{testKey, "", "# comment", testKey})
	if len(keys) != 2 {
		t.Fatalf("parseKeys kept %d entries, want 2", len(keys))
	}
}

func TestSplitLinesMatchesPython(t *testing.T) {
	// Each case is the exact output of Python str.splitlines() on the input.
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a\nb\n", []string{"a", "b"}},
		{"a\nb", []string{"a", "b"}},
		{"a\n\nb\n", []string{"a", "", "b"}},
		{"a\r\nb\n", []string{"a", "b"}},
		{"line\n", []string{"line"}},
		{"a\n\n", []string{"a", ""}},
		{"a\n\n\n", []string{"a", "", ""}},
		{"\n", []string{""}},
		{"\n\n", []string{"", ""}},
	}
	for _, c := range cases {
		got := splitLines(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitLines(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestManageKeysListEmptyHome(t *testing.T) {
	home := t.TempDir()
	keys, err := ManageKeys(home, KeyRequest{Action: "list"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("empty home listed %d keys", len(keys))
	}
	// A list must not create the .ssh directory.
	if _, err := os.Stat(filepath.Join(home, ".ssh")); !os.IsNotExist(err) {
		t.Error("list created .ssh; it should be read-only for a missing dir")
	}
}

func TestManageKeysAddDeleteRoundTrip(t *testing.T) {
	if _, err := os.Stat("/usr/bin/ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available for verifyKey")
	}
	home := t.TempDir()

	keys, err := ManageKeys(home, KeyRequest{Action: "add", Key: testKey})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(keys) != 1 || keys[0].Fingerprint != testKeyFP {
		t.Fatalf("add returned %+v", keys)
	}

	// The file lands with 0600 and the trailing newline the writer appends.
	data, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != testKey+"\n" {
		t.Errorf("file content = %q", string(data))
	}
	info, _ := os.Stat(filepath.Join(home, ".ssh", "authorized_keys"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys mode = %v, want 0600", info.Mode().Perm())
	}

	// A duplicate is rejected by fingerprint.
	if _, err := ManageKeys(home, KeyRequest{Action: "add", Key: testKey}); err == nil {
		t.Error("adding a duplicate key should fail")
	}

	// Delete by id removes it; deleting again fails.
	keys, err = ManageKeys(home, KeyRequest{Action: "delete", ID: testKeyID})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("delete left %d keys", len(keys))
	}
	if _, err := ManageKeys(home, KeyRequest{Action: "delete", ID: testKeyID}); err == nil {
		t.Error("deleting a missing key should fail")
	}
}

func TestManageKeysRejectsOptionsAndGarbage(t *testing.T) {
	if _, err := os.Stat("/usr/bin/ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available for verifyKey")
	}
	home := t.TempDir()
	for _, key := range []string{
		`no-pty ` + testKey,      // options prefix is rejected on add
		"ssh-ed25519 not-base64", // fails ssh-keygen validation
		strings.Repeat("a", 20000),
	} {
		if _, err := ManageKeys(home, KeyRequest{Action: "add", Key: key}); err == nil {
			t.Errorf("add accepted an invalid key %.20q...", key)
		}
	}
}

func TestManageKeysRefusesSymlinkedSSHDir(t *testing.T) {
	home := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(home, ".ssh")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// O_NOFOLLOW on the directory open must refuse to traverse the symlink.
	if _, err := ManageKeys(home, KeyRequest{Action: "add", Key: testKey}); err != errKeyOp {
		t.Errorf("symlinked .ssh: got %v, want errKeyOp", err)
	}
}

func TestManageKeysRejectsOversizedFile(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("x", 131073) + "\n"
	if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ManageKeys(home, KeyRequest{Action: "list"}); err != errKeyOp {
		t.Errorf("oversized file: got %v, want errKeyOp", err)
	}
}

func TestShadowAgingMath(t *testing.T) {
	// expired: an expiry day at or before today has passed; -1 never expires.
	if !expired(ShadowState{ExpiryDay: 1}) {
		t.Error("a day-1 expiry should be expired")
	}
	if expired(ShadowState{ExpiryDay: -1}) {
		t.Error("an unset expiry should never be expired")
	}
	if expired(ShadowState{ExpiryDay: today() + 1}) {
		t.Error("a future expiry should not be expired")
	}

	// passwordInactive needs all three fields set and today past the sum.
	if !passwordInactive(1, 0, 0) {
		t.Error("last=1,max=0,inactive=0 is far in the past and should be inactive")
	}
	if passwordInactive(today(), 30, 30) {
		t.Error("a password changed today with 60 days of slack is not inactive")
	}
	if passwordInactive(0, 30, 30) {
		t.Error("last<=0 disables the inactivity check")
	}
	if passwordInactive(1, -1, 30) {
		t.Error("an unset maxDays disables the inactivity check")
	}
}

func TestPolicyEntryGatesOnUID(t *testing.T) {
	db := policyDB{
		"alice": {"uid": float64(1001), "panel": true},
	}
	// Matching uid returns the record.
	got := policyEntry(db, passwdUser{Name: "alice", UID: 1001})
	if v, _ := got["panel"].(bool); !v {
		t.Error("matching uid should return the stored record")
	}
	// A recreated account with a different uid must not inherit the old record.
	if len(policyEntry(db, passwdUser{Name: "alice", UID: 1002})) != 0 {
		t.Error("stale record (uid mismatch) must not apply")
	}
	// An unknown user gets an empty record.
	if len(policyEntry(db, passwdUser{Name: "bob", UID: 1003})) != 0 {
		t.Error("unknown user should get an empty record")
	}
}
