package folders

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

type folder struct {
	Name   string  `json:"name"`
	Path   string  `json:"path"`
	Reason *string `json:"reason,omitempty"`
}
type listing struct {
	Roots   any      `json:"roots"`
	Path    string   `json:"path"`
	Folders []folder `json:"folders"`
}

func openDirectory(path string) (*os.File, error) {
	if _, err := systemops.CleanPath(path); err != nil {
		return nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), path), nil
}
func children(dir *os.File, path string, validate func(string) error) ([]folder, error) {
	result := []folder{}
	for len(result) < 1000 {
		rows, err := dir.ReadDir(128)
		for _, row := range rows {
			if !row.IsDir() || strings.HasPrefix(row.Name(), ".") || row.Name() == "lost+found" {
				continue
			}
			entry := folder{Name: row.Name(), Path: filepath.Join(path, row.Name())}
			if validate != nil {
				reason := ""
				if e := validate(entry.Path); e != nil {
					reason = e.Error()
				}
				entry.Reason = &reason
			}
			result = append(result, entry)
			if len(result) == 1000 {
				break
			}
		}
		if len(rows) == 0 {
			if err != nil && err != io.EOF {
				return nil, err
			}
			break
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name) })
	return result, nil
}
func Query(ctx context.Context, view, target string) (json.RawMessage, error) {
	return browse(ctx, view, target, run)
}
func browse(ctx context.Context, view, target string, exec command) (json.RawMessage, error) {
	response := listing{Path: target, Folders: []folder{}}
	var validate func(string) error
	allowed := []string{}
	if view == "mount-folders" {
		roots := []string{}
		for _, path := range []string{"/srv", "/mnt"} {
			dir, err := openDirectory(path)
			if err == nil {
				dir.Close()
				roots = append(roots, path)
			}
		}
		response.Roots = roots
		allowed = roots
	} else if view == "home-folders" || view == "data-folders" {
		state, err := readInventory(ctx, exec)
		if err != nil {
			return nil, err
		}
		validate = func(path string) error { _, err := state.volume(path, view == "data-folders"); return err }
		unique := map[string]bool{"/home": true}
		for _, m := range state.mounts {
			if strings.HasPrefix(m.Target, "/home/") || strings.HasPrefix(m.Target, "/srv/") || strings.HasPrefix(m.Target, "/mnt/") {
				unique[m.Target] = true
			}
		}
		paths := []string{}
		for path := range unique {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		roots := []folder{}
		for _, path := range paths {
			dir, err := openDirectory(path)
			if err != nil {
				continue
			}
			dir.Close()
			entry := folder{Name: path, Path: path}
			reason := ""
			if err = validate(path); err != nil {
				reason = err.Error()
			} else {
				allowed = append(allowed, path)
			}
			entry.Reason = &reason
			roots = append(roots, entry)
		}
		response.Roots = roots
	} else {
		return nil, reject("Unknown operation")
	}
	if target == "" {
		return json.Marshal(response)
	}
	if _, err := systemops.CleanPath(target); err != nil {
		return nil, err
	}
	accepted := false
	for _, root := range allowed {
		accepted = accepted || within(target, root)
	}
	if !accepted {
		if view == "mount-folders" {
			return nil, reject("Choose a mount location under /srv or /mnt")
		}
		return nil, reject("Choose a folder on a supported home volume")
	}
	dir, err := openDirectory(target)
	if err != nil {
		return nil, reject("Choose an existing folder without symbolic links")
	}
	defer dir.Close()
	if validate != nil {
		if err = validate(target); err != nil {
			return nil, err
		}
	}
	response.Folders, err = children(dir, target, validate)
	if err != nil {
		return nil, err
	}
	return json.Marshal(response)
}

func OpenDirectory(path string) (*os.File, error) { return openDirectory(path) }
