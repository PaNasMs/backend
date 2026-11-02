package networkmounts

import (
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func hashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
func sameDirectory(file *os.File, path string) error {
	current, err := pinDirectory(path)
	if err != nil {
		return err
	}
	defer current.Close()
	var old, now unix.Stat_t
	if err = unix.Fstat(int(file.Fd()), &old); err != nil {
		return err
	}
	if err = unix.Fstat(int(current.Fd()), &now); err != nil {
		return err
	}
	if old.Dev != now.Dev || old.Ino != now.Ino {
		return reject("The mount point changed; review a new operation plan")
	}
	return nil
}
func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *service) createCredential(state *transaction, p map[string]any) error {
	if err := secureDirectory(s.credentials, s.owner, true); err != nil {
		return err
	}
	path := filepath.Join(s.credentials, Key(state.Point))
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	st := info.Sys().(*syscall.Stat_t)
	state.Credential = true
	state.CredentialDevice = uint64(st.Dev)
	state.CredentialInode = st.Ino
	// Persist ownership before writing the secret; cleanup never removes a replacement inode.
	if err = s.save(state); err != nil {
		return err
	}
	content := "username=" + param(p, "username") + "\npassword=" + param(p, "password") + "\n"
	if domain := param(p, "domain"); domain != "" {
		content += "domain=" + domain + "\n"
	}
	if _, err = file.WriteString(content); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	return syncDirectory(s.credentials)
}
func (s *service) removeCredential(state *transaction) error {
	if !state.Credential {
		return nil
	}
	if err := secureDirectory(s.credentials, s.owner, false); err != nil {
		return err
	}
	path := filepath.Join(s.credentials, Key(state.Point))
	file, err := secureFile(path, s.owner)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := file.Stat()
	file.Close()
	if err != nil {
		return err
	}
	st := info.Sys().(*syscall.Stat_t)
	if uint64(st.Dev) != state.CredentialDevice || st.Ino != state.CredentialInode {
		return reject("Network credentials changed; preserve them and review recovery")
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(s.credentials)
}

type pathWitness struct {
	Ancestor               string
	Device, Inode, MountID uint64
}

func closestDirectory(path string) (pathWitness, *os.File, error) {
	for candidate := path; ; candidate = filepath.Dir(candidate) {
		file, err := pinDirectory(candidate)
		if err != nil {
			if os.IsNotExist(err) && candidate != "/" {
				continue
			}
			return pathWitness{}, nil, err
		}
		var st unix.Stat_t
		var mount unix.Statx_t
		if err = unix.Fstat(int(file.Fd()), &st); err != nil {
			file.Close()
			return pathWitness{}, nil, err
		}
		if err = unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &mount); err != nil {
			file.Close()
			return pathWitness{}, nil, err
		}
		return pathWitness{Ancestor: candidate, Device: st.Dev, Inode: st.Ino, MountID: mount.Mnt_id}, file, nil
	}
}
func createPinnedTarget(point string, expected pathWitness) (*os.File, error) {
	witness, parent, err := closestDirectory(point)
	if err != nil {
		return nil, err
	}
	if witness != expected {
		parent.Close()
		return nil, reject("The mount point changed; review a new operation plan")
	}
	if witness.Ancestor == point {
		return parent, nil
	}
	relative := strings.TrimPrefix(point, strings.TrimRight(witness.Ancestor, "/")+"/")
	for _, part := range strings.Split(relative, "/") {
		if err = unix.Mkdirat(int(parent.Fd()), part, 0755); err != nil && err != unix.EEXIST {
			parent.Close()
			return nil, err
		}
		if err = parent.Sync(); err != nil {
			parent.Close()
			return nil, err
		}
		next, err := unix.Openat(int(parent.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		parent.Close()
		if err != nil {
			return nil, err
		}
		parent = os.NewFile(uintptr(next), point)
	}
	return parent, nil
}

func (s *service) adoptLegacyCredential(state *transaction) error {
	if state.FSType != "cifs" || state.Credential {
		return nil
	}
	if err := secureDirectory(s.credentials, s.owner, false); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	file, err := secureFile(filepath.Join(s.credentials, Key(state.Point)), s.owner)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	st := info.Sys().(*syscall.Stat_t)
	state.Credential = true
	state.CredentialDevice = uint64(st.Dev)
	state.CredentialInode = st.Ino
	return nil
}
