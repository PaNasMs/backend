package volumeaccess

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops/accounts"
)

type mount struct{ id, device, root, point, options, fs, super string }

func unescape(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}
func mounts(data string) []mount {
	var rows []mount
	for _, line := range strings.Split(data, "\n") {
		halves := strings.SplitN(line, " - ", 2)
		if len(halves) != 2 {
			continue
		}
		a, b := strings.Fields(halves[0]), strings.Fields(halves[1])
		if len(a) < 6 || len(b) < 3 {
			continue
		}
		rows = append(rows, mount{a[0], a[2], unescape(a[3]), unescape(a[4]), a[5], b[0], b[2]})
	}
	return rows
}
func systemPath(p string) bool {
	for _, base := range []string{"/", "/boot", "/efi", "/usr", "/var", "/home", "/etc", "/opt"} {
		if p == base || base != "/" && strings.HasPrefix(p, base+"/") {
			return true
		}
	}
	return false
}
func candidates(rows []mount, protected map[string]bool) []mount {
	for _, m := range rows {
		if systemPath(m.point) {
			protected[m.device] = true
		}
	}
	var result []mount
	for _, m := range rows {
		if protected[m.device] || !strings.Contains(","+m.options+",", ",rw,") {
			continue
		}
		if !strings.HasPrefix(m.point, "/srv/") && !strings.HasPrefix(m.point, "/mnt/") && !strings.HasPrefix(m.point, "/media/") {
			continue
		}
		switch m.fs {
		case "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "vfat", "exfat", "ntfs", "ntfs3":
		default:
			continue
		}
		// A bind-mounted directory must not turn into a shared volume root.
		if m.root != "/" && m.fs != "btrfs" {
			continue
		}
		result = append(result, m)
	}
	return result
}
func deviceID(dev uint64) string { return fmt.Sprintf("%d:%d", unix.Major(dev), unix.Minor(dev)) }
func protectedDevices() (map[string]bool, error) {
	result := map[string]bool{}
	data, err := os.ReadFile("/etc/fstab")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(f) < 3 || (!systemPath(unescape(f[1])) && f[2] != "swap") {
			continue
		}
		source := unescape(f[0])
		for _, kind := range []string{"UUID", "PARTUUID", "LABEL", "PARTLABEL"} {
			if strings.HasPrefix(source, kind+"=") {
				source = "/dev/disk/by-" + strings.ToLower(kind) + "/" + strings.TrimPrefix(source, kind+"=")
				break
			}
		}
		var st unix.Stat_t
		if unix.Stat(source, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFBLK {
			result[deviceID(st.Rdev)] = true
		}
	}
	return result, nil
}
func apply(m mount) error {
	fd, err := unix.Open(m.point, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), m.point)
	defer file.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if deviceID(st.Dev) != m.device {
		return fmt.Errorf("mount changed at %s", m.point)
	}
	switch m.fs {
	case "vfat", "exfat", "ntfs", "ntfs3":
		group, err := user.LookupGroup("users")
		if err != nil {
			return err
		}
		if strings.Contains(","+m.super+",", ",gid="+group.Gid+",") && strings.Contains(m.super, "fmask=0113") && strings.Contains(m.super, "dmask=0002") {
			return nil
		}
		return fmt.Errorf("%s: reconnect the volume through Disks to apply shared mount permissions", m.point)
	}
	cmd := exec.Command("setfacl", "-m", "g:users:rwx,d:g:users:rwx", "--", "/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{file}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", m.point, err, out)
	}
	return nil
}
func EnsureUsers() error {
	names, err := accounts.VolumeUsers()
	if err != nil {
		return err
	}
	groups, err := os.ReadFile("/etc/group")
	if err != nil {
		return err
	}
	gid := ""
	members := map[string]bool{}
	for _, line := range strings.Split(string(groups), "\n") {
		f := strings.Split(line, ":")
		if len(f) == 4 && f[0] == "users" {
			gid = f[2]
			for _, n := range strings.Split(f[3], ",") {
				members[n] = true
			}
			break
		}
	}
	if gid == "" {
		return fmt.Errorf("required users group is missing")
	}
	for _, name := range names {
		if members[name] {
			continue
		}
		if out, e := exec.Command("usermod", "-a", "-G", "users", "--", name).CombinedOutput(); e != nil {
			return fmt.Errorf("add NAS user to common group: %w: %s", e, out)
		}
	}
	return nil
}
func Run(once bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	seen := map[string]bool{}
	identity := ""
	for {
		passwd, e := os.ReadFile("/etc/passwd")
		if e != nil {
			return e
		}
		groups, e := os.ReadFile("/etc/group")
		if e != nil {
			return e
		}
		if next := string(passwd) + string(groups); next != identity {
			if e = EnsureUsers(); e != nil {
				return e
			}
			identity = next
		}
		data, e := os.ReadFile("/proc/self/mountinfo")
		if e != nil {
			return e
		}
		protected, e := protectedDevices()
		if e != nil {
			return e
		}
		active := map[string]bool{}
		var failures []string
		for _, m := range candidates(mounts(string(data)), protected) {
			key := m.id + ":" + m.device + ":" + m.point
			if seen[key] {
				active[key] = true
				continue
			}
			if e = apply(m); e != nil {
				failures = append(failures, e.Error())
				active[key] = true
				continue
			}
			active[key] = true
		}
		seen = active
		if len(failures) > 0 {
			if once {
				return fmt.Errorf("%s", strings.Join(failures, "; "))
			}
			fmt.Fprintln(os.Stderr, strings.Join(failures, "; "))
		}
		if once {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(3 * time.Second):
		}
	}
}

func ApplyMounted(point string) error {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	protected, err := protectedDevices()
	if err != nil {
		return err
	}
	for _, m := range candidates(mounts(string(data)), protected) {
		if m.point == point {
			return apply(m)
		}
	}
	return nil
}
