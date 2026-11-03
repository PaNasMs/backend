package modulelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

func maintenanceAncestor(lease *maintenanceLease) (bool, error) {
	var info unix.Stat_t
	if err := unix.Fstat(int(lease.file.Fd()), &info); err != nil {
		return false, err
	}
	ancestors := map[int]bool{}
	pid := os.Getppid()
	for pid > 1 && !ancestors[pid] && len(ancestors) < 128 {
		path := filepath.Join("/proc", strconv.Itoa(pid))
		entry, err := os.Stat(path)
		if err != nil {
			return false, err
		}
		stat, ok := entry.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != lease.owner {
			break
		}
		ancestors[pid] = true
		raw, err := os.ReadFile(filepath.Join(path, "stat"))
		if err != nil {
			return false, err
		}
		n := strings.LastIndex(string(raw), ") ")
		if n < 0 {
			return false, reject("Cannot verify inherited system maintenance")
		}
		tail := string(raw)[n+2:]
		fields := strings.Fields(tail)
		if len(fields) < 2 {
			return false, reject("Cannot verify inherited system maintenance")
		}
		pid, err = strconv.Atoi(fields[1])
		if err != nil {
			return false, err
		}
	}
	raw, err := os.ReadFile("/proc/locks")
	if err != nil {
		return false, err
	}
	for _, row := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(row)
		if len(fields) < 6 || fields[1] != "FLOCK" || fields[2] != "ADVISORY" || fields[3] != "WRITE" {
			continue
		}
		pid, err := strconv.Atoi(fields[4])
		if err != nil || !ancestors[pid] {
			continue
		}
		device := strings.Split(fields[5], ":")
		if len(device) != 3 {
			continue
		}
		major, e1 := strconv.ParseUint(device[0], 16, 32)
		minor, e2 := strconv.ParseUint(device[1], 16, 32)
		inode, e3 := strconv.ParseUint(device[2], 10, 64)
		if e1 == nil && e2 == nil && e3 == nil && major == uint64(unix.Major(info.Dev)) && minor == uint64(unix.Minor(info.Dev)) && inode == info.Ino {
			return true, nil
		}
	}
	return false, nil
}

func (s lifecycle) recoverStartup(ctx context.Context) (err error) {
	restoring := false
	defer func() {
		if err != nil && !restoring {
			err = systemops.BeforeMutation(err)
		}
	}()
	state, err := s.loadTransaction()
	if err != nil || state == nil {
		return err
	}
	lease, err := acquireMaintenance(s.maintenance, s.owner)
	if err != nil {
		return err
	}
	defer lease.file.Close()
	lock, err := s.lock(ctx, nil)
	if err != nil {
		return err
	}
	defer lock.Close()
	state, err = s.loadTransaction()
	if err != nil || state == nil {
		return err
	}
	if state.requiresBarrier() {
		if err = lease.critical(); err != nil {
			return err
		}
	}
	restoring = true
	if err = s.recovery().restore(ctx, state, nil); err != nil && !systemops.Unchanged(err) {
		_ = s.haltAffected(ctx, state, nil)
	}
	return err
}

func (s lifecycle) startup(ctx context.Context, diagnostics io.Writer) error {
	err := s.recoverStartup(ctx)
	if err != nil && systemops.Unchanged(err) {
		_, writeErr := fmt.Fprintln(diagnostics, err)
		return writeErr
	}
	return err
}

func resumeOrder(registry Registry) ([]string, map[string]bool) {
	state, blocked := map[string]int{}, map[string]bool{}
	order := []string{}
	var visit func(string) bool
	visit = func(id string) bool {
		if registry[id] == nil || state[id] == 1 {
			return false
		}
		if state[id] == 2 {
			return !blocked[id]
		}
		state[id] = 1
		deps, err := dependencies(registry[id])
		good := err == nil && registry[id]["enabled"] == true
		for _, dependency := range names(deps) {
			ready := visit(dependency)
			match := false
			if ready {
				match, err = satisfies(text(registry[dependency], "version"), deps[dependency])
			}
			if !ready || err != nil || !match {
				good = false
			}
		}
		state[id], blocked[id] = 2, !good
		order = append(order, id)
		return good
	}
	for _, id := range names(registry) {
		visit(id)
	}
	return order, blocked
}

func (s lifecycle) verifyService(manifest Manifest) error {
	directory, err := trustedDirectory(filepath.Join(s.root, text(manifest, "id"), "bin"), s.owner)
	if err != nil {
		return err
	}
	defer directory.Close()
	raw, err := readOwnedAt(directory, "server", s.owner, maxExpandedArchive)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(raw)
	files, _ := manifest["files"].(map[string]any)
	if files["bin/server"] != hex.EncodeToString(hash[:]) {
		return reject("Module payload changed; update or reinstall the module")
	}
	return nil
}

func (s lifecycle) resume(ctx context.Context) error {
	lease, err := openMaintenance(s.maintenance, s.owner)
	if err != nil {
		return err
	}
	defer lease.file.Close()
	borrowed, err := maintenanceAncestor(lease)
	if err != nil {
		return err
	}
	if !borrowed {
		if err = unix.Flock(int(lease.file.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
			return reject("System maintenance in progress; retry after the update")
		}
	}
	lock, err := s.lock(ctx, nil)
	if err != nil {
		return err
	}
	defer lock.Close()
	if state, err := s.loadTransaction(); err != nil {
		return err
	} else if state != nil {
		return reject(incompleteRecovery)
	}
	if !borrowed {
		if err = lease.critical(); err != nil {
			return err
		}
	}
	if err = s.refreshCore(); err != nil {
		return err
	}
	registry, err := s.registry()
	if err != nil {
		return err
	}
	order, blocked := resumeOrder(registry)
	failed := []string{}
	for _, id := range order {
		m := registry[id]
		if m["enabled"] != true || text(m, "service") == "" {
			continue
		}
		if blocked[id] {
			failed = append(failed, id)
			continue
		}
		dependencies, _ := dependencies(m)
		for dependency := range dependencies {
			if registry[dependency]["enabled"] != true || blocked[dependency] {
				blocked[id] = true
			}
		}
		if blocked[id] {
			failed = append(failed, id)
			continue
		}
		if err = validateManifest(m, s.core, s.architecture, false); err == nil {
			err = s.verifyService(m)
		}
		if err == nil {
			err = writeUnit(s.root, s.units, m, s.owner)
		}
		if err == nil {
			_, err = s.run(ctx, []string{"systemctl", "daemon-reload"}, systemops.CommandOptions{Operation: true})
		}
		if err == nil {
			err = startModule(ctx, m, s.run, s.health, nil)
		}
		if err != nil {
			blocked[id] = true
			failed = append(failed, id)
		}
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		return reject("Modules not started: " + strings.Join(failed, ", ") + ". Open Modules to update or reinstall them.")
	}
	return nil
}

func Command(ctx context.Context, mode string, out io.Writer) error {
	s, err := installedLifecycle()
	if err != nil {
		return err
	}
	switch mode {
	case "recover":
		return s.recoverStartup(ctx)
	case "startup":
		return s.startup(ctx, os.Stderr)
	case "resume":
		return s.resume(ctx)
	case "check-install":
		state, err := s.loadTransaction()
		if err != nil {
			return err
		}
		if state != nil {
			return reject("Recover pending module transactions with the installed version before package changes")
		}
		return nil
	case "inspect":
		raw, err := Inspect()
		if err == nil {
			_, err = out.Write(raw)
		}
		return err
	default:
		return reject("Unknown module lifecycle command")
	}
}
