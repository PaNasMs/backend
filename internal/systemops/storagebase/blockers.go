package storagebase

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"panasms.local/backend/internal/systemops/folders"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type StoragePath struct{ Name, Path string }

func inside(path, root string) bool {
	return path == root || strings.HasPrefix(path, strings.TrimRight(root, "/")+"/")
}
func configuredInside(path, root string) (bool, error) {
	if inside(path, root) {
		return true, nil
	}
	resolved, err := resolveConfigured(path, 0)
	return err == nil && inside(resolved, root), err
}
func resolveConfigured(path string, depth int) (string, error) {
	if !filepath.IsAbs(path) || depth > 64 {
		return "", reject("Could not inspect configured storage paths")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", reject("Could not inspect configured storage paths")
	}
	// Keep a configured missing leaf bound to its existing symlinked ancestor.
	if info, e := os.Lstat(path); e == nil && info.Mode()&os.ModeSymlink != 0 {
		target, e := os.Readlink(path)
		if e != nil {
			return "", reject("Could not inspect configured storage paths")
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		return resolveConfigured(target, depth+1)
	}
	parent := filepath.Dir(path)
	if parent == path {
		return "", reject("Could not inspect configured storage paths")
	}
	resolved, err = resolveConfigured(parent, depth+1)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(path)), nil
}
func CheckBlockers(ctx context.Context, selected, all []folders.LiveMount, homes, shares []StoragePath, exports []string) error {
	return checkBlockers(ctx, "/proc", selected, all, homes, shares, exports)
}
func checkBlockers(ctx context.Context, proc string, selected, all []folders.LiveMount, homes, shares []StoragePath, exports []string) error {
	if len(selected) == 0 {
		return nil
	}
	points := map[string]bool{}
	ids := map[uint64]string{}
	mappedDevices := map[string][]string{}
	for _, m := range selected {
		points[m.Target] = true
		ids[m.ID] = m.Target
		if m.Device != "" {
			majorText, minorText, ok := strings.Cut(m.Device, ":")
			major, majorErr := strconv.ParseUint(majorText, 10, 32)
			minor, minorErr := strconv.ParseUint(minorText, 10, 32)
			if !ok || majorErr != nil || minorErr != nil {
				return reject("Could not verify process mount identity")
			}
			key := fmt.Sprintf("%02x:%02x", major, minor)
			mappedDevices[key] = append(mappedDevices[key], m.Target)
			if m.FSType == "btrfs" {
				var st unix.Statx_t
				if err := unix.Statx(unix.AT_FDCWD, m.Target, unix.AT_STATX_DONT_SYNC, unix.STATX_MNT_ID, &st); err != nil || st.Mnt_id != m.ID {
					return reject("Could not verify process mount identity")
				}
				rootKey := fmt.Sprintf("%02x:%02x", st.Dev_major, st.Dev_minor)
				if rootKey != key {
					mappedDevices[rootKey] = append(mappedDevices[rootKey], m.Target)
				}
			}
		}
	}
	problems := []string{}
	for _, m := range selected {
		for _, nested := range all {
			if nested.Target != m.Target && inside(nested.Target, m.Target) && !points[nested.Target] {
				problems = append(problems, fmt.Sprintf("Mounted inside “%s”: %s. Unmount these nested mounts first.", m.Target, nested.Target))
			}
		}
		for _, home := range homes {
			used, err := configuredInside(home.Path, m.Target)
			if err != nil {
				return err
			}
			if used {
				problems = append(problems, "User home folders on this volume: "+home.Name+": "+home.Path+". Move these homes before unmounting the volume.")
			}
		}
		for _, share := range shares {
			used, err := configuredInside(share.Path, m.Target)
			if err != nil {
				return err
			}
			if used {
				problems = append(problems, "Shared folders on this volume: "+share.Name+" ("+share.Path+"). Remove their shares in Shared folders first.")
			}
		}
		for _, path := range exports {
			used, err := configuredInside(path, m.Target)
			if err != nil {
				return err
			}
			if used {
				problems = append(problems, "Folders shared via NFS: "+path+". Remove their shares in Shared folders first.")
			}
		}
	}
	processes, err := os.ReadDir(proc)
	if err != nil {
		return err
	}
	for _, entry := range processes {
		if err = ctx.Err(); err != nil {
			return err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || pid == os.Getpid() {
			continue
		}
		root := filepath.Join(proc, entry.Name())
		busy := map[string]bool{}
		// Cloned namespaces can assign another mount ID to the same filesystem.
		recordUse := func(path string) error {
			var st unix.Statx_t
			err := unix.Statx(unix.AT_FDCWD, path, unix.AT_STATX_DONT_SYNC|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &st)
			if processGone(err) {
				return nil
			}
			if err != nil {
				return reject("Could not check which processes use the volume. No unmount has started.")
			}
			if point := ids[st.Mnt_id]; point != "" {
				busy[point] = true
			}
			for _, point := range mappedDevices[fmt.Sprintf("%02x:%02x", st.Dev_major, st.Dev_minor)] {
				busy[point] = true
			}
			return nil
		}
		for _, link := range []string{"cwd", "root"} {
			if err := recordUse(filepath.Join(root, link)); err != nil {
				return err
			}
		}
		descriptors, err := os.ReadDir(filepath.Join(root, "fdinfo"))
		if err != nil {
			if processGone(err) {
				continue
			}
			return reject("Could not check which processes use the volume. No unmount has started.")
		}
		for _, fd := range descriptors {
			data, err := os.ReadFile(filepath.Join(root, "fdinfo", fd.Name()))
			if err != nil {
				if processGone(err) {
					continue
				}
				return reject("Could not check which processes use the volume. No unmount has started.")
			}
			if len(mappedDevices) > 0 {
				if err := recordUse(filepath.Join(root, "fd", fd.Name())); err != nil {
					return err
				}
			}
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "mnt_id:") {
					id, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "mnt_id:")), 10, 64)
					if err != nil {
						return reject("Could not verify process mount identity")
					}
					if point := ids[id]; point != "" {
						busy[point] = true
					}
				}
			}
		}
		if len(mappedDevices) > 0 {
			if err := mappedVolumes(filepath.Join(root, "maps"), mappedDevices, busy); err != nil && !processGone(err) {
				return reject("Could not check which processes use the volume. No unmount has started.")
			}
		}
		if len(busy) == 0 {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(root, "comm"))
		if err != nil {
			if processGone(err) {
				continue
			}
			return err
		}
		name := strings.TrimSpace(string(comm))
		cg, err := os.ReadFile(filepath.Join(root, "cgroup"))
		if err != nil && !processGone(err) {
			return err
		}
		unit := ""
		for _, part := range strings.FieldsFunc(string(cg), func(r rune) bool { return r == '/' || r == '\n' }) {
			if strings.HasSuffix(part, ".service") {
				unit = part
			}
		}
		if unit != "" {
			name += " [" + unit + "]"
		}
		status, err := os.Stat(root)
		if err != nil {
			if processGone(err) {
				continue
			}
			return err
		}
		uid := status.Sys().(*syscall.Stat_t).Uid
		for point := range busy {
			problems = append(problems, fmt.Sprintf("Volume “%s” is busy: %s (PID %d, UID %d). Close the files or stop the relevant service; if this is a terminal, leave the volume's directory.", point, name, pid, uid))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return reject(strings.Join(problems, " "))
	}
	return nil
}
func processGone(err error) bool { return os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) }

func mappedVolumes(path string, devices map[string][]string, busy map[string]bool) error {
	maps, err := os.Open(path)
	if err != nil {
		return err
	}
	defer maps.Close()
	scanner := bufio.NewScanner(maps)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			return reject("Could not verify process mount identity")
		}
		// File mappings keep the filesystem busy even after the descriptor closes.
		if fields[4] != "0" {
			for _, point := range devices[fields[3]] {
				busy[point] = true
			}
		}
	}
	return scanner.Err()
}
