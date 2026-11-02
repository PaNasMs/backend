package networkmounts

import (
	"context"
	"encoding/json"
	"os"
	"os/user"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/folders"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) (*service, map[string]any) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(root, "fstab")
	if err := os.WriteFile(conf, []byte("UUID=root / ext4 defaults 0 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return &service{proc: filepath.Join(root, "proc"), root: filepath.Join(root, "state"), owner: os.Geteuid(), write: func(path, text string, mode os.FileMode) error { return os.WriteFile(path, []byte(text), mode) }, fstab: conf, credentials: filepath.Join(root, "credentials"), mounts: func() ([]folders.LiveMount, error) { return []folders.LiveMount{}, nil }, lookup: func(string) (*user.User, error) { return &user.User{Uid: "1000", Gid: "1000"}, nil }, path: func(p string) error { _, err := systemops.CleanPath(p); return err }, run: func(context.Context, []string, systemops.CommandOptions) ([]byte, error) { return nil, nil }}, map[string]any{"target": "//nas/share", "point": filepath.Join(root, "share"), "username": "member", "password": "secret-value", "automount": true}
}
func TestPlanDoesNotCreateOrExposeCredentials(t *testing.T) {
	s, p := fixture(t)
	raw, err := s.plan(context.Background(), "smb.mount", p, "member")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-value") {
		t.Fatal(string(raw))
	}
	for _, path := range []string{param(p, "point"), s.credentials} {
		if _, err = os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal(path, err)
		}
	}
	var first, second map[string]any
	json.Unmarshal(raw, &first)
	p["password"] = "replacement-secret"
	raw, err = s.plan(context.Background(), "smb.mount", p, "member")
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(raw, &second)
	if first["fingerprint"] != second["fingerprint"] {
		t.Fatal("secret included in fingerprint")
	}
}
func TestPlanRejectsInjectionDuplicateAndNestedMount(t *testing.T) {
	for _, reason := range []string{"credentials", "duplicate", "nested", "symlink", "mode", "occupied"} {
		t.Run(reason, func(t *testing.T) {
			s, p := fixture(t)
			point := param(p, "point")
			switch reason {
			case "credentials":
				p["password"] = "x\nusername=evil"
			case "duplicate":
				os.WriteFile(s.fstab, []byte("nas:/data "+point+" nfs defaults 0 0\n"), 0600)
			case "nested":
				s.mounts = func() ([]folders.LiveMount, error) {
					return []folders.LiveMount{{Target: point + "/nested", FSType: "ext4"}}, nil
				}
			case "symlink":
				os.Symlink(t.TempDir(), point)
			case "mode":
				p["automount"] = "true"
			case "occupied":
				os.Mkdir(point, 0700)
				os.WriteFile(filepath.Join(point, "data"), []byte("keep"), 0600)
			}
			if _, err := s.plan(context.Background(), "smb.mount", p, "member"); err == nil {
				t.Fatal(reason)
			}
		})
	}
}
func TestUnmountRequiresExactTypeAndNoBusyProcesses(t *testing.T) {
	s, p := fixture(t)
	point := param(p, "point")
	params := map[string]any{"target": point}
	s.mounts = func() ([]folders.LiveMount, error) {
		return []folders.LiveMount{{ID: 42, Target: point, FSType: "cifs", Source: "//nas/share"}}, nil
	}
	if _, err := s.plan(context.Background(), "nfs.unmount", params, "member"); err == nil {
		t.Fatal("wrong type accepted")
	}
	s.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
		return []byte("123 456"), nil
	}
	if _, err := s.plan(context.Background(), "smb.unmount", params, "member"); err == nil || (!strings.Contains(err.Error(), "123") || !strings.Contains(err.Error(), "456")) {
		t.Fatal(err)
	}
}
