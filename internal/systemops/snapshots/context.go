package snapshots

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
)

const directoryName = ".panasms-snapshots"

func reject(s string) error { return &systemops.Rejected{Message: s} }

type subvolumeInfo struct {
	ID, Generation uint64
	UUID           [16]byte
	ReadOnly       bool
}

// BTRFS_IOC_GET_SUBVOL_INFO returns the containing tree even for an ordinary
// directory. Only inode 256 itself can serve as a subvolume root.
func subvolume(f *os.File) (subvolumeInfo, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return subvolumeInfo{}, err
	}
	if st.Ino != 256 {
		return subvolumeInfo{}, reject("Select a Btrfs subvolume")
	}
	var info struct {
		ID                             uint64
		Name                           [256]byte
		Parent, Dir, Generation, Flags uint64
		UUID                           [16]byte
		Rest                           [192]byte
	}
	const getSubvolInfo = uintptr(0x81f8943c)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), getSubvolInfo, uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(f)
	if errno != 0 {
		return subvolumeInfo{}, errno
	}
	// GET_SUBVOL_INFO reports on-disk root-item flags, whose read-only bit
	// differs from BTRFS_SUBVOL_RDONLY used by SNAP_CREATE_V2 and GETFLAGS.
	const rootSubvolReadonly = 1 << 0
	return subvolumeInfo{ID: info.ID, Generation: info.Generation, UUID: info.UUID, ReadOnly: info.Flags&rootSubvolReadonly != 0}, nil
}

type volume struct {
	Target, Point, UUID string
	Identity            storagequery.StorageIdentity
	Device              *storagebase.PinnedDevice
	Root, Directory     *os.File
	RootInfo            subvolumeInfo
	Mount               folders.LiveMount
	members             []string
}

func (v *volume) Close() {
	if v.Directory != nil {
		v.Directory.Close()
	}
	if v.Root != nil {
		v.Root.Close()
	}
	if v.Device != nil {
		v.Device.Close()
	}
}

func mountpoint(row map[string]any) (string, error) {
	if row["fstype"] != "btrfs" {
		return "", reject("Snapshots require a Btrfs file system")
	}
	var point string
	points, _ := row["mountpoints"].([]any)
	for _, value := range points {
		path, _ := value.(string)
		if path == "" {
			continue
		}
		if point != "" {
			return "", reject("Mount the Btrfs volume at one location first")
		}
		point = path
	}
	if point == "" {
		return "", reject("Mount the Btrfs volume at one location first")
	}
	return point, folders.MountPath(point)
}

// Btrfs mountinfo uses an anonymous device number. Kernel sysfs links identify
// the actual mounted members, including on a multi-device file system.
func mountedMembers(uuid string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join("/sys/fs/btrfs", uuid, "devices"))
	if err != nil {
		return nil, err
	}
	var devices []string
	for _, entry := range entries {
		resolved, err := filepath.EvalSymlinks(filepath.Join("/sys/fs/btrfs", uuid, "devices", entry.Name()))
		if err != nil {
			return nil, err
		}
		devices = append(devices, filepath.Join("/dev", filepath.Base(resolved)))
	}
	sort.Strings(devices)
	return devices, nil
}

func loadVolume(ctx context.Context, input string) (*volume, error) {
	if !strings.HasPrefix(input, "/dev/") || filepath.Clean(input) != input {
		return nil, reject("Select a block device")
	}
	target, err := filepath.EvalSymlinks(input)
	if err != nil || filepath.Dir(target) != "/dev" {
		return nil, reject("The device no longer exists")
	}
	pf, err := storagequery.LoadPreflight(ctx)
	if err != nil {
		return nil, err
	}
	if err = pf.Protected(target, false); err != nil {
		return nil, err
	}
	row := pf.Inventory.Rows[target]
	point, err := mountpoint(row)
	if err != nil {
		return nil, err
	}
	v := &volume{Target: target, Point: point}
	keep := false
	defer func() {
		if !keep {
			v.Close()
		}
	}()
	v.Root, err = folders.OpenDirectory(point)
	if err != nil {
		return nil, err
	}
	rows, err := folders.ReadMounts()
	if err != nil {
		return nil, err
	}
	v.Mount, err = folders.DirectoryMount(v.Root, rows)
	if err != nil {
		return nil, err
	}
	if v.Mount.Target != point || v.Mount.FSType != "btrfs" {
		return nil, reject("The mount changed; review a new operation plan")
	}
	v.UUID, err = storagebase.BtrfsUUID(v.Root)
	if err != nil {
		return nil, err
	}
	expected, _ := row["uuid"].(string)
	if expected == "" || !strings.EqualFold(v.UUID, expected) {
		return nil, reject("The Btrfs file system changed")
	}
	v.members, err = mountedMembers(v.UUID)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(v.members, target) {
		return nil, reject("The Btrfs backing device changed")
	}
	v.Identity, err = pf.Identity(target)
	if err != nil {
		return nil, err
	}
	devices := map[string]storagequery.DeviceIdentity{}
	for _, d := range v.Identity.Devices {
		devices[d.Path] = d
		if d.Path == target {
			v.Device, err = storagebase.PinDevice(d)
			if err != nil {
				return nil, err
			}
		}
	}
	if v.Device == nil {
		return nil, reject("Could not verify storage identity")
	}
	for _, member := range v.members {
		if member == target {
			continue
		}
		if err = pf.Protected(member, false); err != nil {
			return nil, err
		}
		id, err := pf.Identity(member)
		if err != nil {
			return nil, err
		}
		if id.BootID != v.Identity.BootID {
			return nil, reject("The Btrfs backing device changed")
		}
		for _, d := range id.Devices {
			if old, ok := devices[d.Path]; ok && old != d {
				return nil, reject("The Btrfs backing device changed")
			}
			devices[d.Path] = d
		}
	}
	v.Identity.Devices = nil
	for _, d := range devices {
		v.Identity.Devices = append(v.Identity.Devices, d)
	}
	sort.Slice(v.Identity.Devices, func(i, j int) bool { return v.Identity.Devices[i].Path < v.Identity.Devices[j].Path })
	v.RootInfo, err = subvolume(v.Root)
	if err != nil {
		return nil, err
	}
	if err = v.writable(); err != nil {
		return nil, err
	}
	v.Directory, err = v.openDirectory()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	keep = true
	return v, nil
}

func (v *volume) writable() error {
	var s unix.Statfs_t
	if err := unix.Fstatfs(int(v.Root.Fd()), &s); err != nil {
		return err
	}
	if s.Flags&unix.ST_RDONLY != 0 || v.RootInfo.ReadOnly {
		return reject("The destination is read-only. Check the file system before retrying.")
	}
	return nil
}

func child(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (v *volume) openDirectory() (*os.File, error) {
	f, err := child(v.Root, directoryName)
	if err != nil {
		return nil, err
	}
	var s unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &s); err != nil {
		f.Close()
		return nil, err
	}
	if s.Uid != 0 || s.Mode&0077 != 0 {
		f.Close()
		return nil, reject("The snapshot directory must be owned by root and private")
	}
	return f, nil
}

func (v *volume) snapshot(name string) (*os.File, subvolumeInfo, error) {
	if _, err := systemops.Name(name); err != nil {
		return nil, subvolumeInfo{}, err
	}
	if v.Directory == nil {
		return nil, subvolumeInfo{}, reject("Snapshot no longer exists")
	}
	f, err := child(v.Directory, name)
	if err != nil {
		return nil, subvolumeInfo{}, err
	}
	info, err := subvolume(f)
	if err == nil && !info.ReadOnly {
		err = reject("Only read-only snapshots managed by PaNasMs can be used here")
	}
	if err != nil {
		f.Close()
		return nil, subvolumeInfo{}, err
	}
	return f, info, nil
}

func (v *volume) verify() error {
	if err := v.Device.Verify(); err != nil {
		return err
	}
	members, err := mountedMembers(v.UUID)
	if err != nil {
		return err
	}
	if !slices.Equal(members, v.members) {
		return reject("The Btrfs backing device changed")
	}
	root, err := folders.OpenDirectory(v.Point)
	if err != nil {
		return err
	}
	defer root.Close()
	rows, err := folders.ReadMounts()
	if err != nil {
		return err
	}
	mount, err := folders.DirectoryMount(root, rows)
	if err != nil {
		return err
	}
	info, err := subvolume(root)
	if err != nil {
		return err
	}
	if mount != v.Mount || info.ID != v.RootInfo.ID || info.UUID != v.RootInfo.UUID || info.ReadOnly != v.RootInfo.ReadOnly {
		return reject("The mount changed; review a new operation plan")
	}
	if err = v.writable(); err != nil {
		return err
	}
	dir, err := v.openDirectory()
	if errors.Is(err, os.ErrNotExist) && v.Directory == nil {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	if v.Directory == nil {
		return reject("The snapshot directory changed")
	}
	observed, err := dir.Stat()
	if err != nil {
		return err
	}
	pinned, err := v.Directory.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(observed, pinned) {
		return reject("The snapshot directory changed")
	}
	return nil
}

func Query(ctx context.Context, target string) (json.RawMessage, error) {
	v, err := loadVolume(ctx, target)
	if err != nil {
		return nil, err
	}
	defer v.Close()
	rows := []map[string]string{}
	if v.Directory != nil {
		names, err := v.Directory.Readdirnames(-1)
		if err != nil {
			return nil, err
		}
		sort.Strings(names)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			f, _, err := v.snapshot(name)
			if err != nil {
				// Ordinary entries and names disappearing during enumeration do not represent snapshots.
				if systemops.IsRejected(err) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
					continue
				}
				return nil, err
			}
			f.Close()
			rows = append(rows, map[string]string{"name": name})
		}
	}
	if err := v.verify(); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"target": v.Target, "point": v.Point, "snapshots": rows})
}
