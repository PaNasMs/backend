package folders

import (
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"os/user"
	"panasms.local/backend/internal/systemops"
	"path/filepath"
	"strconv"
	"testing"
)

func TestPermissionFingerprintPreservesNumericIdentity(t *testing.T) {
	params := map[string]any{"target": "/srv/data/folder", "mode": "0750"}
	fp, err := permissionFingerprint(params, []any{uint64(9007199254740993), uint32(1000)})
	if err != nil {
		t.Fatal(err)
	}
	want, err := systemops.Fingerprint("folder.permissions", params, []any{json.Number("9007199254740993"), json.Number("1000")})
	if err != nil || fp != want {
		t.Fatal(fp, want, err)
	}
}

func permissionFixture(t *testing.T) (permissionService, map[string]any) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "selected")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	uid := os.Geteuid()
	if uid < 1000 {
		uid = 1000
	}
	service := permissionService{path: func(path string) error { _, err := systemops.CleanPath(path); return err }, owner: func(string) (*user.User, error) { return &user.User{Uid: strconv.Itoa(uid)}, nil }, group: func(string) (*user.Group, error) { return &user.Group{Gid: strconv.Itoa(os.Getegid())}, nil }, mount: func(*os.File) (LiveMount, error) { return LiveMount{ID: 42, Target: "/fixture", FSType: "ext4"}, nil }}
	return service, map[string]any{"target": path, "owner": "member", "group": "users", "mode": "0750"}
}
func TestPermissionMutationIsNonrecursiveAndRejectsReplacement(t *testing.T) {
	for _, replace := range []bool{false, true} {
		s, p := permissionFixture(t)
		path := param(p, "target")
		child := filepath.Join(path, "child")
		os.Mkdir(child, 0700)
		planned, err := s.prepare(p)
		if err != nil {
			t.Fatal(err)
		}
		fp := planned.fingerprint
		planned.file.Close()
		if replace {
			if err = os.Rename(path, path+"-original"); err != nil {
				t.Fatal(err)
			}
			os.Mkdir(path, 0700)
		}
		_, err = s.execute(p, fp)
		if replace {
			if err == nil || !systemops.Unchanged(err) {
				t.Fatal(err)
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0700 {
				t.Fatal(info.Mode())
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0750 {
			t.Fatal(info.Mode())
		}
		info, _ = os.Stat(child)
		if info.Mode().Perm() != 0700 {
			t.Fatal(info.Mode())
		}
	}
}
func TestPermissionOperationPreservesDefaultACL(t *testing.T) {
	s, p := permissionFixture(t)
	path := param(p, "target")
	// Linux POSIX ACL xattr: version2 and owner/group/other default entries.
	acl := []byte{2, 0, 0, 0, 1, 0, 7, 0, 255, 255, 255, 255, 4, 0, 5, 0, 255, 255, 255, 255, 32, 0, 0, 0, 255, 255, 255, 255}
	if err := unix.Setxattr(path, "system.posix_acl_default", acl, 0); err == unix.EOPNOTSUPP {
		t.Skip("fixture filesystem lacks POSIX ACL")
	} else if err != nil {
		t.Fatal(err)
	}
	planned, err := s.prepare(p)
	if err != nil {
		t.Fatal(err)
	}
	fp := planned.fingerprint
	planned.file.Close()
	if _, err = s.execute(p, fp); err != nil {
		t.Fatal(err)
	}
	result := make([]byte, 128)
	n, err := unix.Getxattr(path, "system.posix_acl_default", result)
	if err != nil || string(result[:n]) != string(acl) {
		t.Fatal(result[:n], err)
	}
}
