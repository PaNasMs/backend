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
	if Pending() {
		return nil, errors.New("Recover the recorded module transaction before using installed modules")
	}
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
	var selected, disabled *Manifest
	registrations := map[string]string{}
	for key, m := range entries {
		if !m.Enabled {
			names := m.Actions
			if kind == "queries" {
				names = m.Queries
			}
			for _, n := range names {
				if n == name && m.Operations != "" {
					copy := m
					disabled = &copy
				}
			}
			continue
		}
		names := m.Actions
		if kind == "queries" {
			names = m.Queries
		}
		matches := false
		for _, n := range names {
			matches = matches || n == name
		}
		if !matches {
			continue
		}
		if selected != nil {
			return nil, errors.New("conflicting module registration")
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
				owner, seen := registrations[k+":"+n]
				if n != prefix && !strings.HasPrefix(n, prefix+".") || reserved(k, n) || (seen && owner != key) {
					return nil, errors.New("conflicting module registration")
				}
				if seen {
					continue
				}
				registrations[k+":"+n] = key
				if k == kind && n == name {
					copy := m
					selected = &copy
				}
			}
		}
	}
	if selected == nil {
		selected = disabled
	}
	if selected != nil && selected.Operations != "" && (selected.API != 1 || selected.Operations != "bin/server" || selected.Files["bin/server"] == "") {
		return nil, errors.New("unsupported module operation protocol")
	}
	return selected, nil
}

// A shared lifecycle lock keeps disable/update/remove from replacing the
// verified payload until the selected operation has finished.
func Lock(trustedUID uint32) (*os.File, error) {
	fd, err := unix.Open(filepath.Join(Root, ".lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "module lifecycle lock")
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != trustedUID || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("unsafe module lifecycle lock")
	}
	if err = unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func VerifyOperation(m *Manifest, trustedUID uint32) (*os.File, error) {
	executable := filepath.Join(Root, m.ID, "bin/server")
	for _, path := range []string{Root, filepath.Join(Root, "registry.json"), filepath.Join(Root, m.ID), filepath.Join(Root, m.ID, "bin"), executable} {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != trustedUID || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("unsafe installed module payload")
		}
	}
	fd, err := unix.Open(executable, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "verified module executable")
	valid := false
	defer func() {
		if !valid {
			f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != trustedUID || info.Mode().Perm()&0022 != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("invalid module executable")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return nil, err
	}
	if hex.EncodeToString(h.Sum(nil)) != m.Files["bin/server"] {
		return nil, errors.New("installed module checksum mismatch")
	}
	valid = true
	return f, nil
}
