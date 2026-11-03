package modulelifecycle

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type store struct {
	root  string
	owner uint32
}

func trustedDirectory(path string, owner uint32) (*os.File, error) {
	return trustedDirectoryMode(path, owner, false)
}

func trustedDirectoryMode(path string, owner uint32, stickyLeaf bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, reject("Module state permissions are unsafe")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var namespace unix.Stat_t
	if err = unix.Fstat(fd, &namespace); err != nil {
		unix.Close(fd)
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, part := range parts {
		if part == "" {
			unix.Close(fd)
			return nil, reject("Module state permissions are unsafe")
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
		var stat unix.Stat_t
		if err = unix.Fstat(fd, &stat); err != nil {
			unix.Close(fd)
			return nil, err
		}
		final := index == len(parts)-1
		stickyAncestor := (!final || stickyLeaf) && stat.Uid == namespace.Uid && stat.Mode&unix.S_ISVTX != 0
		if (stat.Uid != owner && (final || stat.Uid != namespace.Uid)) || stat.Mode&0022 != 0 && !stickyAncestor {
			unix.Close(fd)
			return nil, reject("Module state permissions are unsafe")
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func readOwnedAt(directory *os.File, name string, owner uint32, maximum int64) ([]byte, error) {
	raw, _, err := readOwnedSnapshotAt(directory, name, owner, maximum)
	return raw, err
}

func readOwnedSnapshotAt(directory *os.File, name string, owner uint32, maximum int64) ([]byte, unix.Stat_t, error) {
	var stat unix.Stat_t
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, stat, reject("Invalid module state path")
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, stat, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if err = unix.Fstat(fd, &stat); err != nil {
		return nil, stat, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != owner || stat.Nlink != 1 || stat.Mode&0022 != 0 {
		return nil, stat, reject("Module state permissions are unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, stat, err
	}
	if int64(len(raw)) > maximum {
		return nil, stat, reject("Module state is too large")
	}
	var current unix.Stat_t
	if err = unix.Fstatat(int(directory.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, stat, err
	}
	if stat.Dev != current.Dev || stat.Ino != current.Ino || stat.Mode != current.Mode || stat.Uid != current.Uid || stat.Gid != current.Gid || stat.Nlink != current.Nlink || stat.Size != current.Size || stat.Mtim != current.Mtim || stat.Ctim != current.Ctim {
		return nil, stat, reject("Module state changed while it was read")
	}
	return raw, stat, nil
}

func (s store) registry() (Registry, error) {
	dir, err := trustedDirectory(s.root, s.owner)
	if errors.Is(err, unix.ENOENT) {
		return Registry{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	raw, err := readOwnedAt(dir, "registry.json", s.owner, 8<<20)
	if errors.Is(err, unix.ENOENT) {
		return Registry{}, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeRegistry(raw)
}

func atomicAt(directory *os.File, name string, raw []byte, mode uint32, owner uint32) error {
	return atomicOwnedAt(directory, name, raw, mode, owner, uint32(os.Getegid()))
}

func atomicOwnedAt(directory *os.File, name string, raw []byte, mode uint32, owner, group uint32) error {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return reject("Invalid module state path")
	}
	var previous unix.Stat_t
	err := unix.Fstatat(int(directory.Fd()), name, &previous, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err == nil && (previous.Mode&unix.S_IFMT != unix.S_IFREG || previous.Uid != owner || previous.Nlink != 1 || previous.Mode&0022 != 0) {
		return reject("Module state permissions are unsafe")
	}
	existed := err == nil
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := ".write-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(int(directory.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	defer file.Close()
	defer unix.Unlinkat(int(directory.Fd()), temporary, 0)
	var created unix.Stat_t
	if err = unix.Fstat(fd, &created); err != nil {
		return err
	}
	if created.Uid != owner || created.Gid != group {
		if err = file.Chown(int(owner), int(group)); err != nil {
			return err
		}
	}
	if err = file.Chmod(os.FileMode(mode)); err != nil {
		return err
	}
	if _, err = file.Write(raw); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if existed {
		var current unix.Stat_t
		if err = unix.Fstatat(int(directory.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if previous.Dev != current.Dev || previous.Ino != current.Ino || previous.Mode != current.Mode || previous.Uid != current.Uid || previous.Gid != current.Gid || previous.Nlink != current.Nlink || previous.Size != current.Size || previous.Mtim != current.Mtim || previous.Ctim != current.Ctim {
			return reject("Module state changed before replacement; current files were preserved")
		}
		err = unix.Renameat(int(directory.Fd()), temporary, int(directory.Fd()), name)
	} else {
		err = unix.Renameat2(int(directory.Fd()), temporary, int(directory.Fd()), name, unix.RENAME_NOREPLACE)
	}
	if err != nil {
		return err
	}
	return directory.Sync()
}

func (s store) saveRegistry(registry Registry) error {
	raw, err := json.Marshal(registry)
	if err != nil {
		return err
	}
	if _, err = decodeRegistry(raw); err != nil {
		return err
	}
	dir, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		return err
	}
	defer dir.Close()
	return atomicAt(dir, "registry.json", raw, 0644, s.owner)
}

func listModules(registry Registry, core string, member bool) (map[string]any, error) {
	copy, err := copyRegistry(registry)
	if err != nil {
		return nil, err
	}
	installed := []Manifest{}
	for _, id := range names(copy) {
		manifest := copy[id]
		if member && id != "files" && manifest["memberAccess"] != true {
			continue
		}
		requiredBy, err := dependents(id, copy)
		if err != nil {
			return nil, err
		}
		manifest["requiredBy"] = requiredBy
		installed = append(installed, manifest)
	}
	return map[string]any{"core": core, "api": 1, "installed": installed}, nil
}
