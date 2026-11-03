package storagebase

import (
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
func CheckBlockers(ctx context.Context, selected, all []folders.LiveMount, homes, shares []StoragePath, exports []string) error {
	return checkBlockers(ctx, "/proc", selected, all, homes, shares, exports)
}
func checkBlockers(ctx context.Context, proc string, selected, all []folders.LiveMount, homes, shares []StoragePath, exports []string) error {
	if len(selected) == 0 {
		return nil
	}
	points := map[string]bool{}
	ids := map[uint64]string{}
	for _, m := range selected {
		points[m.Target] = true
		ids[m.ID] = m.Target
	}
	problems := []string{}
	for _, m := range selected {
		for _, nested := range all {
			if nested.Target != m.Target && inside(nested.Target, m.Target) && !points[nested.Target] {
				problems = append(problems, fmt.Sprintf("Mounted inside “%s”: %s. Unmount these nested mounts first.", m.Target, nested.Target))
			}
		}
		for _, home := range homes {
			if inside(home.Path, m.Target) {
				problems = append(problems, "User home folders on this volume: "+home.Name+": "+home.Path+". Move these homes before unmounting the volume.")
			}
		}
		for _, share := range shares {
			if inside(share.Path, m.Target) {
				problems = append(problems, "Shared folders on this volume: "+share.Name+" ("+share.Path+"). Remove their shares in Shared folders first.")
			}
		}
		for _, path := range exports {
			if inside(path, m.Target) {
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
		for _, link := range []string{"cwd", "root"} {
			var st unix.Statx_t
			err = unix.Statx(unix.AT_FDCWD, filepath.Join(root, link), 0, unix.STATX_MNT_ID, &st)
			if err != nil {
				if processGone(err) {
					continue
				}
				return reject("Could not check which processes use the volume. No unmount has started.")
			}
			if point := ids[st.Mnt_id]; point != "" {
				busy[point] = true
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
