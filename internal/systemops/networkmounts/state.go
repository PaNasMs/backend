package networkmounts

import (
	"encoding/json"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type transaction struct {
	BootID           string `json:"bootID"`
	Stage            bool   `json:"stage,omitempty"`
	Schema           int    `json:"schema"`
	Point            string `json:"point"`
	Source           string `json:"source"`
	FSType           string `json:"fstype"`
	Phase            string `json:"phase"`
	MountID          uint64 `json:"mountID,omitempty"`
	Credential       bool   `json:"credential,omitempty"`
	CredentialDevice uint64 `json:"credentialDevice,omitempty"`
	CredentialInode  uint64 `json:"credentialInode,omitempty"`
	BeforeHash       string `json:"beforeHash"`
	AfterHash        string `json:"afterHash,omitempty"`
}

func secureDirectory(path string, owner int, create bool) error {
	if err := safePath(path); err != nil {
		return err
	}
	namespaceRoot, err := os.Stat("/")
	if err != nil {
		return err
	}
	rootUID := namespaceRoot.Sys().(*syscall.Stat_t).Uid
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			st := info.Sys().(*syscall.Stat_t)
			stickyRoot := st.Uid == rootUID && info.Mode()&os.ModeSticky != 0
			if !info.IsDir() || (int(st.Uid) != owner && st.Uid != rootUID) || (info.Mode().Perm()&0022 != 0 && !stickyRoot) {
				return reject("Network mount state permissions are unsafe")
			}
		}
		if parent == "/" {
			break
		}
	}
	if create {
		if err := os.MkdirAll(path, 0700); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 || int(info.Sys().(*syscall.Stat_t).Uid) != owner {
		return reject("Network mount state permissions are unsafe")
	}
	return nil
}
func secureFile(path string, owner int) (*os.File, error) {
	if err := safePath(filepath.Dir(path)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	st := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || int(st.Uid) != owner || st.Nlink != 1 {
		file.Close()
		return nil, reject("Network mount state permissions are unsafe")
	}
	return file, nil
}
func (s *service) load(point string) (*transaction, error) {
	if err := secureDirectory(s.root, s.owner, false); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	file, err := secureFile(filepath.Join(s.root, Key(point)+".json"), s.owner)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return nil, err
	}
	if len(raw) > 65536 {
		return nil, reject("Network mount state is too large")
	}
	var state transaction
	if err = json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	if state.Schema != 1 || state.Point != point || (state.FSType != "nfs" && state.FSType != "cifs") {
		return nil, reject("Network mount recovery state is invalid")
	}
	switch state.Phase {
	case "preparing", "staged", "attaching", "mounted", "unmounted":
	default:
		return nil, reject("Network mount recovery state is invalid")
	}
	return &state, nil
}
func (s *service) save(state *transaction) error {
	if state.BootID == "" {
		boot, err := currentBootID()
		if err != nil {
			return err
		}
		state.BootID = boot
	}
	if err := secureDirectory(s.root, s.owner, true); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return s.write(filepath.Join(s.root, Key(state.Point)+".json"), string(raw)+"\n", 0600)
}
func (s *service) lock() (*os.File, error) {
	if err := secureDirectory(s.root, s.owner, true); err != nil {
		return nil, err
	}
	path := filepath.Join(s.root, "operation.lock")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	st := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || int(st.Uid) != s.owner || st.Nlink != 1 {
		file.Close()
		return nil, reject("Network mount state permissions are unsafe")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, reject("Another network mount operation is in progress")
	}
	return file, nil
}
func (s *service) removeState(point string) error {
	path := filepath.Join(s.root, Key(point)+".json")
	file, err := secureFile(path, s.owner)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	file.Close()
	if err = os.Remove(path); err != nil {
		return err
	}
	dir, err := os.Open(s.root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func currentBootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", reject("Network mount boot identity is unavailable")
	}
	return value, nil
}
