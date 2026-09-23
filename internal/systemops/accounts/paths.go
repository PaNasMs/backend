package accounts

import (
	"context"
	"encoding/json"
	"os"
	"panasms.local/backend/internal/systemops"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func newHome(p map[string]any, target string) (string, error) {
	if value := stringParam(p, "home"); value != "" {
		return value, nil
	}
	base := "/home"
	raw, err := os.ReadFile("/etc/default/useradd")
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "HOME=") {
			base = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "HOME=")), "\"'")
		}
	}
	if !filepath.IsAbs(base) || filepath.Clean(base) != base {
		return "", reject("Invalid default home directory")
	}
	return filepath.Join(base, target), nil
}
func childOf(path, parent string) bool {
	return path == parent || strings.HasPrefix(path, strings.TrimRight(parent, "/")+"/")
}
func noLinks(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return reject("Links in the home folder path are not allowed")
		}
		if p == "/" {
			break
		}
	}
	return nil
}
func validateHome(path, target string, existing bool, users []passwdUser) error {
	if _, err := systemops.CleanPath(path); err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n\x00") {
		return reject("Invalid home folder")
	}
	if !(strings.HasPrefix(path, "/home/") || strings.HasPrefix(path, "/srv/") || strings.HasPrefix(path, "/mnt/")) || filepath.Base(path) == "lost+found" {
		return reject("The home folder must be under /home, /srv or /mnt")
	}
	if err := noLinks(path); err != nil {
		return err
	}
	for _, u := range users {
		if u.Name != target && (childOf(u.Dir, path) || (u.Dir != "/" && u.Dir != "/nonexistent" && childOf(path, u.Dir))) {
			return reject("The path overlaps another user's home folder")
		}
	}
	info, err := os.Stat(path)
	if existing {
		if err != nil || !info.IsDir() {
			return reject("Home folder unavailable")
		}
		u, _ := getpwnam(users, target)
		if int(info.Sys().(*syscall.Stat_t).Uid) != u.UID {
			return reject("The home folder belongs to another user")
		}
	} else {
		if err == nil {
			return reject("Destination folder already exists")
		}
		if !os.IsNotExist(err) {
			return err
		}
		parent, err := os.Stat(filepath.Dir(path))
		if err != nil || !parent.IsDir() {
			return reject("Destination parent folder is unavailable")
		}
	}
	var mounts struct {
		Filesystems []mount `json:"filesystems"`
	}
	if err := readCommandJSON([]string{"findmnt", "--json", "--list", "--output", "TARGET,FSTYPE,OPTIONS,MAJ:MIN"}, &mounts); err != nil {
		return err
	}
	best := mount{}
	for _, m := range mounts.Filesystems {
		if existing && childOf(m.Target, path) {
			return reject("The home folder contains mounts")
		}
		if childOf(path, m.Target) && len(m.Target) > len(best.Target) {
			best = m
		}
	}
	if strings.HasPrefix(path, "/srv/") || strings.HasPrefix(path, "/mnt/") {
		if best.Target == "/" || best.Target == "" || best.Target == path {
			return reject("The home volume is unavailable or the path is a volume root")
		}
	}
	if existing {
		return nil
	}
	return homeVolume(best)
}

type mount struct {
	Target  string `json:"target"`
	FSType  string `json:"fstype"`
	Options string `json:"options"`
	Device  string `json:"maj:min"`
}

func readCommandJSON(args []string, v any) error {
	raw, err := systemops.Command(context.Background(), args, systemops.CommandOptions{})
	if err != nil {
		return err
	}
	return systemops.Decode(raw, v)
}
func homeVolume(m mount) error {
	if !contains([]string{"ext2", "ext3", "ext4", "xfs", "btrfs"}, m.FSType) || !contains(strings.Split(m.Options, ","), "rw") {
		return reject("Choose a writable local Linux filesystem for home folders")
	}
	type device struct {
		Name      string            `json:"name"`
		ID        string            `json:"maj:min"`
		Type      string            `json:"type"`
		Removable json.RawMessage   `json:"rm"`
		Transport string            `json:"tran"`
		Children  []json.RawMessage `json:"children"`
	}
	var raw struct {
		Devices []json.RawMessage `json:"blockdevices"`
	}
	if err := readCommandJSON([]string{"lsblk", "--json", "--output", "NAME,MAJ:MIN,TYPE,RM,TRAN"}, &raw); err != nil {
		return err
	}
	local := map[string]bool{}
	unsafe := map[string]bool{}
	var walk func(json.RawMessage, bool) error
	walk = func(raw json.RawMessage, parentUnsafe bool) error {
		var d device
		if err := systemops.Decode(raw, &d); err != nil {
			return err
		}
		bad := parentUnsafe || d.Transport == "usb" || string(d.Removable) == "true" || (string(d.Removable) == "1" || string(d.Removable) == `"1"`) || d.Type == "loop"
		local[d.ID] = true
		unsafe[d.ID] = unsafe[d.ID] || bad
		for _, child := range d.Children {
			if err := walk(child, bad); err != nil {
				return err
			}
		}
		return nil
	}
	for _, d := range raw.Devices {
		if err := walk(d, false); err != nil {
			return err
		}
	}
	if !local[m.Device] || unsafe[m.Device] {
		return reject("Home folders require a permanent local disk; removable and USB devices are not supported")
	}
	if m.Target != "/" {
		var configured struct {
			Filesystems []mount `json:"filesystems"`
		}
		if err := readCommandJSON([]string{"findmnt", "--fstab", "--json", "--output", "TARGET,OPTIONS"}, &configured); err != nil {
			return err
		}
		found := false
		for _, f := range configured.Filesystems {
			if f.Target == m.Target && !contains(strings.Split(f.Options, ","), "noauto") {
				found = true
			}
		}
		if !found {
			return reject("Configure this volume to mount automatically before moving home folders")
		}
	}
	return nil
}
func homeIdle(u passwdUser) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	blockers := []string{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		root := "/proc/" + e.Name()
		status, err := os.ReadFile(root + "/status")
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if exitedProcess(string(status)) {
			continue
		}
		info, err := os.Stat(root)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		used := int(info.Sys().(*syscall.Stat_t).Uid) == u.UID
		paths := []string{root + "/cwd", root + "/root"}
		fds, err := os.ReadDir(root + "/fd")
		if err != nil && !os.IsNotExist(err) {
			return reject("Cannot inspect process " + e.Name() + " while checking home-folder use: " + err.Error())
		}
		for _, fd := range fds {
			paths = append(paths, root+"/fd/"+fd.Name())
		}
		for _, path := range paths {
			link, err := os.Readlink(path)
			if err == nil && childOf(strings.TrimSuffix(link, " (deleted)"), u.Dir) {
				used = true
			}
		}
		if used {
			comm, _ := os.ReadFile(root + "/comm")
			title := strings.TrimSpace(string(comm))
			cg, _ := os.ReadFile(root + "/cgroup")
			for _, part := range strings.FieldsFunc(string(cg), func(r rune) bool { return r == '/' || r == '\n' }) {
				if strings.HasSuffix(part, ".service") {
					title = part
				}
			}
			switch {
			case strings.Contains(title, "cloud-sync"):
				title = "Cloud Sync"
			case strings.Contains(title, "terminal"):
				title = "Terminal"
			case strings.Contains(title, "sshd"):
				title = "SSH session"
			case strings.HasPrefix(title, "user@"):
				title = "User session"
			}
			if title == "" {
				title = "Process " + e.Name()
			}
			item := u.Name + ": " + title
			if !contains(blockers, item) {
				blockers = append(blockers, item)
			}
		}
	}
	if len(blockers) > 0 {
		return reject("Home folders are in use. Close these sessions or applications: " + strings.Join(blockers, "; "))
	}
	return nil
}

func exitedProcess(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "State:") {
			fields := strings.Fields(line)
			return len(fields) > 1 && (fields[1] == "Z" || fields[1] == "X")
		}
	}
	return false
}
