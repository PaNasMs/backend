package modules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// The root-owned registry is the installed receipt of signature verification.
// Package installation does not retain the signed manifest or signature.
func Operation(kind, name string, reserved func(string, string) bool) (*Manifest, error) {
	file, err := os.Open(filepath.Join(Root, "registry.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 8<<20 {
		return nil, errors.New("module registry too large")
	}
	var entries map[string]Manifest
	if err = json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	var selected *Manifest
	registrations := map[string]bool{}
	for key, m := range entries {
		if !m.Enabled {
			continue
		}
		if !ID.MatchString(key) || m.ID != key {
			return nil, errors.New("invalid module registration")
		}
		for k, names := range map[string][]string{"actions": m.Actions, "queries": m.Queries} {
			prefix := key
			if key == "files" && k == "actions" {
				prefix = "file"
			}
			for _, n := range names {
				if n != prefix && !strings.HasPrefix(n, prefix+".") || reserved(k, n) || registrations[k+":"+n] {
					return nil, errors.New("conflicting module registration")
				}
				registrations[k+":"+n] = true
				if k == kind && n == name {
					copy := m
					selected = &copy
				}
			}
		}
	}
	if selected != nil && selected.Operations != "" && (selected.API != 1 || selected.Operations != "bin/server" || selected.Files["bin/server"] == "") {
		return nil, errors.New("unsupported module operation protocol")
	}
	return selected, nil
}

// A shared lifecycle lock keeps disable/update/remove from replacing the
// verified payload until the selected operation has finished.
func Lock() (*os.File, error) {
	fd, err := unix.Open(filepath.Join(Root, ".lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "module lifecycle lock")
	if err = unix.Flock(fd, unix.LOCK_SH); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func VerifyOperation(m *Manifest, trustedUID uint32) (string, error) {
	executable := filepath.Join(Root, m.ID, "bin/server")
	for _, path := range []string{Root, filepath.Join(Root, "registry.json"), filepath.Join(Root, m.ID), filepath.Join(Root, m.ID, "bin"), executable} {
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != trustedUID || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return "", errors.New("unsafe installed module payload")
		}
	}
	f, err := os.Open(executable)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", errors.New("invalid module executable")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	if hex.EncodeToString(h.Sum(nil)) != m.Files["bin/server"] {
		return "", errors.New("installed module checksum mismatch")
	}
	return executable, nil
}
