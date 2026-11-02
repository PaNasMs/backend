package folders

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func TestPersonalBrowserIdentityAndHomeBoundary(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	outside := filepath.Join(root, "outside")
	for _, p := range []string{home, outside, filepath.Join(home, "Visible"), filepath.Join(home, ".hidden")} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(home, "linked")); err != nil {
		t.Fatal(err)
	}
	account := &user.User{Uid: strconv.Itoa(os.Geteuid()), Gid: strconv.Itoa(os.Getegid()), HomeDir: home}
	raw, err := personalAccount(account, home)
	if err != nil {
		t.Fatal(err)
	}
	var result listing
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Folders) != 1 || result.Folders[0].Name != "Visible" {
		t.Fatal(result)
	}
	for _, path := range []string{outside, filepath.Join(home, "linked"), filepath.Join(home, "missing")} {
		if _, err = personalAccount(account, path); err == nil {
			t.Fatal(path)
		}
	}
	account.Uid = strconv.Itoa(os.Geteuid() + 1)
	if _, err = personalAccount(account, ""); err == nil {
		t.Fatal("foreign identity accepted")
	}
}

func TestPersonalBrowserSearchOnlyAncestor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root permission proof")
	}
	parent := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(parent, "member")
	if err := os.MkdirAll(filepath.Join(home, "Visible"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0111); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0700)
	if _, err := os.ReadDir(home); err != nil {
		t.Fatal(err)
	}
	account := &user.User{Uid: strconv.Itoa(os.Geteuid()), Gid: strconv.Itoa(os.Getegid()), HomeDir: home}
	raw, err := personalAccount(account, home)
	if err != nil {
		t.Fatal(err)
	}
	var result listing
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Folders) != 1 || result.Folders[0].Name != "Visible" {
		t.Fatal(string(raw))
	}
}
