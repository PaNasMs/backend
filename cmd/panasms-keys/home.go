package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
)

func deleteHomeContents() error {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return fmt.Errorf("owner credentials required")
	}
	if err := unix.Fchdir(3); err != nil {
		return err
	}
	root, err := os.OpenRoot(".")
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := root.RemoveAll(name); err != nil {
			return err
		}
	}
	return nil
}
func deleteHome(username string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root required")
	}
	u, err := user.Lookup(username)
	if err != nil {
		return err
	}
	cred, err := credentialsFor(u)
	if err != nil {
		return err
	}
	cred.Groups = []uint32{}
	path := filepath.Clean(u.HomeDir)
	if path == "/" || !filepath.IsAbs(path) {
		return fmt.Errorf("unsafe home")
	}
	// Open every ancestor without following links; keep both directory descriptors
	// across the unprivileged cleanup so rename races cannot redirect root's removal.
	fd, err := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return err
		}
		fd = next
	}
	defer unix.Close(fd)
	name := filepath.Base(path)
	homeFD, err := unix.Openat(fd, name, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	home := os.NewFile(uintptr(homeFD), "home")
	defer home.Close()
	var before unix.Stat_t
	if err := unix.Fstat(homeFD, &before); err != nil {
		return err
	}
	if before.Uid != cred.Uid {
		return fmt.Errorf("home owner changed")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(executable, "--home-worker")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	cmd.ExtraFiles = []*os.File{home}
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstatat(fd, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		return fmt.Errorf("home changed during cleanup")
	}
	return unix.Unlinkat(fd, name, unix.AT_REMOVEDIR)
}
