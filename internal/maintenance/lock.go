package maintenance

import (
	"errors"
	"os"
	"syscall"
)

// The installer creates this root-owned inode; it must never be replaced while running.
func Acquire() (func(), error) {
	path := os.Getenv("PANASMS_MAINTENANCE_LOCK")
	if path == "" {
		return func() {}, nil
	}
	return AcquirePath(path)
}

func AcquirePath(path string) (func(), error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("Maintenance lock unavailable")
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("System maintenance in progress; retry after the update")
	}
	return func() { file.Close() }, nil
}
