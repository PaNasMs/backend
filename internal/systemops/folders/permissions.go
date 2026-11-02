package folders

import (
	"encoding/json"
	"os"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

func param(p map[string]any, key string) string { value, _ := p[key].(string); return value }
func MountPath(path string) error {
	if _, err := systemops.CleanPath(path); err != nil {
		return err
	}
	if !strings.HasPrefix(path, "/srv/") && !strings.HasPrefix(path, "/mnt/") && !strings.HasPrefix(path, "/media/") {
		return reject("The mount point must be under /srv, /mnt or /media")
	}
	return nil
}

type permissionState struct {
	file        *os.File
	uid, gid    int
	mode        uint32
	fingerprint string
}

type permissionService struct {
	path  func(string) error
	owner func(string) (*user.User, error)
	group func(string) (*user.Group, error)
	mount func(*os.File) (LiveMount, error)
}

func defaultPermissions() permissionService {
	return permissionService{path: MountPath, owner: user.Lookup, group: user.LookupGroup, mount: func(file *os.File) (LiveMount, error) {
		rows, err := ReadMounts()
		if err != nil {
			return LiveMount{}, err
		}
		return DirectoryMount(file, rows)
	}}
}
func (s permissionService) prepare(p map[string]any) (*permissionState, error) {
	path := param(p, "target")
	if err := s.path(path); err != nil {
		return nil, err
	}
	if strings.ContainsAny(path, " \t\\\"") {
		return nil, reject("The share path must not contain spaces or quotation marks")
	}
	for _, key := range []string{"owner", "group"} {
		if _, err := systemops.Name(param(p, key)); err != nil {
			return nil, err
		}
	}
	owner, err := s.owner(param(p, "owner"))
	if err != nil {
		return nil, err
	}
	group, err := s.group(param(p, "group"))
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(owner.Uid)
	if err != nil {
		return nil, err
	}
	if uid < 1000 {
		return nil, reject("Select a regular user")
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, mode := range []string{"0700", "0750", "0770", "0755", "0775", "2770", "2775"} {
		allowed = allowed || param(p, "mode") == mode
	}
	if !allowed {
		return nil, reject("Invalid permissions")
	}
	mode, _ := strconv.ParseUint(param(p, "mode"), 8, 32)
	file, err := openDirectory(path)
	if err != nil {
		return nil, reject("Directory does not exist")
	}
	if err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, reject("Another operation is using this folder")
	}
	keep := false
	defer func() {
		if !keep {
			file.Close()
		}
	}()
	mount, err := s.mount(file)
	if err != nil {
		return nil, err
	}
	if mount.Target == "/" || mount.FSType == "nfs" || mount.FSType == "nfs4" || mount.FSType == "cifs" || mount.FSType == "autofs" {
		return nil, reject("The shared folder must be on a mounted local volume")
	}
	linux := false
	for _, fs := range []string{"ext2", "ext3", "ext4", "xfs", "btrfs"} {
		linux = linux || mount.FSType == fs
	}
	if !linux {
		return nil, reject("This file system does not support the selected Unix permissions")
	}
	var st unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &st); err != nil {
		return nil, err
	}
	fp, err := permissionFingerprint(p, []any{st.Dev, st.Ino, st.Uid, st.Gid, st.Mode, mount.ID, uid, gid})
	if err != nil {
		return nil, err
	}
	keep = true
	return &permissionState{file: file, uid: uid, gid: gid, mode: uint32(mode), fingerprint: fp}, nil
}
func PlanPermissions(p map[string]any) (json.RawMessage, error) {
	state, err := defaultPermissions().prepare(p)
	if err != nil {
		return nil, err
	}
	defer state.file.Close()
	return json.Marshal(map[string]any{"target": param(p, "target"), "confirmation": param(p, "target"), "details": []string{param(p, "target"), "Owner: " + param(p, "owner"), "Group: " + param(p, "group"), "Permissions: " + param(p, "mode"), "Apply only to the selected folder, without recursion"}, "fingerprint": state.fingerprint})
}
func ExecutePermissions(p map[string]any, expected string) (json.RawMessage, error) {
	return defaultPermissions().execute(p, expected)
}
func (s permissionService) execute(p map[string]any, expected string) (json.RawMessage, error) {
	state, err := s.prepare(p)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer state.file.Close()
	if expected == "" || expected != state.fingerprint {
		return nil, systemops.BeforeMutation(reject("State has changed. Review a new operation plan."))
	}
	if err = unix.Fchown(int(state.file.Fd()), state.uid, state.gid); err != nil {
		return nil, err
	}
	if err = unix.Fchmod(int(state.file.Fd()), state.mode); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"message": "Folder ownership and permissions updated"})
}

func permissionFingerprint(params map[string]any, state any) (string, error) {
	raw, err := json.Marshal([]any{params, state})
	if err != nil {
		return "", err
	}
	var decoded []any
	if err = systemops.Decode(raw, &decoded); err != nil {
		return "", err
	}
	return systemops.Fingerprint("folder.permissions", decoded[0].(map[string]any), decoded[1])
}

func PermissionState(target string) (map[string]any, error) {
	if err := MountPath(target); err != nil {
		return nil, err
	}
	file, err := openDirectory(target)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &st); err != nil {
		return nil, err
	}
	return map[string]any{"path": target, "uid": st.Uid, "gid": st.Gid, "mode": strconv.FormatUint(uint64(st.Mode&07777), 8)}, nil
}
