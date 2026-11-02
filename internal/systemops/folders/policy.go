package folders

import (
	"context"
	"encoding/json"
	"strings"

	"panasms.local/backend/internal/systemops"
)

type Mount struct {
	Target  string `json:"target"`
	FSType  string `json:"fstype"`
	Options string `json:"options"`
	Device  string `json:"maj:min"`
	UUID    string `json:"uuid"`
}
type device struct {
	ID        string          `json:"maj:min"`
	Kind      string          `json:"type"`
	Removable json.RawMessage `json:"rm"`
	Transport string          `json:"tran"`
	FSType    string          `json:"fstype"`
	UUID      string          `json:"uuid"`
	Children  []device        `json:"children"`
}
type inventory struct {
	mounts     []Mount
	persistent []Mount
	local      map[string]bool
	removable  map[string]bool
}
type command func(context.Context, []string) ([]byte, error)

func run(ctx context.Context, args []string) ([]byte, error) {
	return systemops.Command(ctx, args, systemops.CommandOptions{})
}
func reject(message string) error { return &systemops.Rejected{Message: message} }
func within(path, root string) bool {
	return path == root || strings.HasPrefix(path, strings.TrimRight(root, "/")+"/")
}
func option(options, value string) bool {
	for _, v := range strings.Split(options, ",") {
		if v == value {
			return true
		}
	}
	return false
}
func readInventory(ctx context.Context, exec command) (inventory, error) {
	s := inventory{local: map[string]bool{}, removable: map[string]bool{}}
	var active, configured struct {
		Filesystems []Mount `json:"filesystems"`
	}
	var disks struct {
		Devices []device `json:"blockdevices"`
	}
	for _, step := range []struct {
		args []string
		into any
	}{
		{[]string{"findmnt", "--json", "--list", "--output", "TARGET,FSTYPE,OPTIONS,MAJ:MIN,UUID"}, &active},
		{[]string{"findmnt", "--fstab", "--json", "--output", "TARGET,OPTIONS"}, &configured},
		{[]string{"lsblk", "--json", "--output", "NAME,MAJ:MIN,TYPE,RM,TRAN,FSTYPE,UUID"}, &disks},
	} {
		raw, err := exec(ctx, step.args)
		if err != nil {
			return s, err
		}
		if err = json.Unmarshal(raw, step.into); err != nil {
			return s, err
		}
	}
	s.mounts, s.persistent = active.Filesystems, configured.Filesystems
	members := map[string][]string{}
	var visit func([]device, bool)
	visit = func(rows []device, inherited bool) {
		for _, d := range rows {
			unsafe := inherited || d.Kind == "loop" || d.Transport == "usb" || string(d.Removable) == "true" || string(d.Removable) == "1" || string(d.Removable) == `"1"`
			if d.ID != "" {
				s.local[d.ID] = true
				s.removable[d.ID] = s.removable[d.ID] || unsafe
				if d.FSType == "btrfs" && d.UUID != "" {
					members[d.UUID] = append(members[d.UUID], d.ID)
				}
			}
			visit(d.Children, unsafe)
		}
	}
	visit(disks.Devices, false)
	for _, m := range s.mounts {
		if m.FSType == "btrfs" && m.Device != "" && len(members[m.UUID]) > 0 {
			s.local[m.Device] = true
			for _, id := range members[m.UUID] {
				s.removable[m.Device] = s.removable[m.Device] || s.removable[id]
			}
		}
	}
	return s, nil
}
func (s inventory) volume(path string, dataOnly bool) (Mount, error) {
	best := Mount{}
	for _, m := range s.mounts {
		if within(path, m.Target) && len(m.Target) > len(best.Target) {
			best = m
		}
	}
	if best.Target == "" {
		return best, reject("The destination volume is unavailable")
	}
	linux := false
	for _, fs := range []string{"ext2", "ext3", "ext4", "xfs", "btrfs"} {
		linux = linux || best.FSType == fs
	}
	if !linux || !option(best.Options, "rw") {
		return best, reject("Choose a writable local Linux filesystem for home folders")
	}
	if !s.local[best.Device] {
		return best, reject("The destination volume is unavailable")
	}
	if s.removable[best.Device] {
		return best, reject("Home folders cannot be stored on USB or removable devices")
	}
	persistent := best.Target == "/"
	for _, m := range s.persistent {
		persistent = persistent || (m.Target == best.Target && !option(m.Options, "noauto"))
	}
	if !persistent {
		return best, reject("Configure automatic mounting for the destination volume first")
	}
	if (strings.HasPrefix(path, "/srv/") || strings.HasPrefix(path, "/mnt/")) && best.Target == "/" {
		return best, reject("The home volume is unavailable or the path is a volume root")
	}
	if dataOnly && (best.Target == "/" || best.Target == "/boot" || best.Target == "/boot/firmware" || (best.FSType != "ext4" && best.FSType != "xfs" && best.FSType != "btrfs")) {
		return best, reject("Choose a mounted writable local data filesystem, not the system disk or a network share")
	}
	return best, nil
}
