package storagebase

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"panasms.local/backend/internal/systemops/storagequery"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"
)

type PinnedDevice struct {
	File     *os.File
	Identity storagequery.DeviceIdentity
}

func PinDevice(identity storagequery.DeviceIdentity) (*PinnedDevice, error) {
	if filepath.Dir(identity.Path) != "/dev" || !deviceName.MatchString(filepath.Base(identity.Path)) {
		return nil, reject("Select a block device")
	}
	fd, err := unix.Open(identity.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), identity.Path)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, err
	}
	number := fmt.Sprintf("%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev))
	if st.Mode&unix.S_IFMT != unix.S_IFBLK || number != identity.DeviceNumber {
		f.Close()
		return nil, reject("The block device changed. Review a new operation plan.")
	}
	p := &PinnedDevice{File: f, Identity: identity}
	if err = p.Verify(); err != nil {
		f.Close()
		return nil, err
	}
	return p, nil
}
func (p *PinnedDevice) Path() string { return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), p.File.Fd()) }
func (p *PinnedDevice) Close() error { return p.File.Close() }

func (p *PinnedDevice) Verify() error {
	var sequence uint64
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, p.File.Fd(), uintptr(unix.BLKGETDISKSEQ), uintptr(unsafe.Pointer(&sequence)))
	runtime.KeepAlive(p.File)
	if errno != 0 {
		return errno
	}
	if strconv.FormatUint(sequence, 10) != p.Identity.DiskSequence {
		return reject("The block device changed. Review a new operation plan.")
	}
	var current unix.Stat_t
	if err := unix.Lstat(p.Identity.Path, &current); err != nil || current.Mode&unix.S_IFMT != unix.S_IFBLK || fmt.Sprintf("%d:%d", unix.Major(current.Rdev), unix.Minor(current.Rdev)) != p.Identity.DeviceNumber {
		return reject("The block device changed. Review a new operation plan.")
	}
	return verifyPublishedDevice(p.Identity, "/sys/dev/block")
}

func verifyPublishedDevice(identity storagequery.DeviceIdentity, sysRoot string) error {
	changed := func() error { return reject("The block device changed. Review a new operation plan.") }
	node := filepath.Join(sysRoot, identity.DeviceNumber)
	before, err := os.Stat(node)
	if err != nil || !before.IsDir() {
		return changed()
	}
	sequencePath := filepath.Join(node, "diskseq")
	if _, err := os.Stat(filepath.Join(node, "partition")); err == nil {
		// Resolve the kernel's dev-number symlink before walking to its parent disk.
		sequencePath = node + "/../diskseq"
	} else if !os.IsNotExist(err) {
		return changed()
	}
	dev, err := os.ReadFile(filepath.Join(node, "dev"))
	if err != nil || strings.TrimSpace(string(dev)) != identity.DeviceNumber {
		return changed()
	}
	seq, err := os.ReadFile(sequencePath)
	if err != nil || strings.TrimSpace(string(seq)) != identity.DiskSequence {
		return changed()
	}
	after, err := os.Stat(node)
	if err != nil || !os.SameFile(before, after) {
		return changed()
	}
	return nil
}
