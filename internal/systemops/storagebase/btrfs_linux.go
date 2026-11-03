package storagebase

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"
)

type btrfsInfo struct {
	MaxID, Devices uint64
	UUID           [16]byte
	Padding        [992]byte
}

func readBtrfsInfo(dir *os.File) (btrfsInfo, string, error) {
	var fs btrfsInfo
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, dir.Fd(), uintptr(0x8400941f), uintptr(unsafe.Pointer(&fs)))
	runtime.KeepAlive(dir)
	if errno != 0 {
		return fs, "", errno
	}
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", fs.UUID[0:4], fs.UUID[4:6], fs.UUID[6:8], fs.UUID[8:10], fs.UUID[10:16])
	return fs, uuid, nil
}

func BtrfsUUID(dir *os.File) (string, error) {
	_, uuid, err := readBtrfsInfo(dir)
	return uuid, err
}

// Btrfs mountinfo uses an anonymous device number. Bind the pinned mounted
// directory to the selected single backing device through kernel ioctls.
func VerifyBtrfsMount(dir *os.File, target, expectedUUID string) error {
	fs, uuid, err := readBtrfsInfo(dir)
	if err != nil {
		return err
	}
	if fs.Devices != 1 || expectedUUID == "" || uuid != strings.ToLower(expectedUUID) {
		return reject("Multi-device or changed Btrfs volumes require a separate workflow")
	}
	var device struct {
		ID          uint64
		UUID        [16]byte
		Used, Total uint64
		FSID        [16]byte
		Padding     [377]uint64
		Path        [1024]byte
	}
	device.ID = fs.MaxID
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, dir.Fd(), uintptr(0xd000941e), uintptr(unsafe.Pointer(&device)))
	runtime.KeepAlive(dir)
	if errno != 0 {
		return errno
	}
	raw := string(device.Path[:])
	end := strings.IndexByte(raw, 0)
	if end < 0 {
		return reject("Could not verify Btrfs backing device")
	}
	path, err := filepath.EvalSymlinks(raw[:end])
	if err != nil || path != target {
		return reject("The mount changed; review a new operation plan")
	}
	return nil
}
