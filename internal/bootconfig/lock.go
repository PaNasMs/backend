package bootconfig

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func Lock() (func(), error) { return lock("/run/lock/panasms-boot-config.lock") }
func lock(path string) (func(), error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("Boot configuration is already being updated")
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
