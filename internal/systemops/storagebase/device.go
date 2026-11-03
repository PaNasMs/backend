package storagebase

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"panasms.local/backend/internal/systemops/storagequery"
	"path/filepath"
	"runtime"
	"strconv"
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
	return nil
}
