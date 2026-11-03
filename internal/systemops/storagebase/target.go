package storagebase

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
)

func SameDirectory(file *os.File, path string) error {
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

type TargetWitness struct {
	Ancestor               string
	Device, Inode, MountID uint64
}

func ObserveTarget(path string) (TargetWitness, *os.File, error) {
	for candidate := path; ; candidate = filepath.Dir(candidate) {
		file, err := pinDirectory(candidate)
		if err != nil {
			if os.IsNotExist(err) && candidate != "/" {
				continue
			}
			return TargetWitness{}, nil, err
		}
		var st unix.Stat_t
		var mount unix.Statx_t
		if err = unix.Fstat(int(file.Fd()), &st); err != nil {
			file.Close()
			return TargetWitness{}, nil, err
		}
		if err = unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &mount); err != nil {
			file.Close()
			return TargetWitness{}, nil, err
		}
		return TargetWitness{Ancestor: candidate, Device: st.Dev, Inode: st.Ino, MountID: mount.Mnt_id}, file, nil
	}
}
func CreateTarget(point string, expected TargetWitness) (*os.File, error) {
	witness, parent, err := ObserveTarget(point)
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
