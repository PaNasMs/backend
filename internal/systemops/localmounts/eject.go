package localmounts

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
	"path/filepath"
	"strings"
)

func (s *service) eject(ctx context.Context, v *plan, pin *storagebase.PinnedDevice, state *transaction, save func(*transaction) error, r *systemops.Reporter) error {
	for _, mount := range v.selected {
		m := mount
		if err := step(state, "unmount:"+m.Target, save, func() error { return storagebase.UnmountPinned(m.Target, m) }); err != nil {
			return err
		}
	}
	return step(state, "disconnect-device", save, func() error {
		fresh, err := s.load(ctx)
		if err != nil {
			return err
		}
		if err = fresh.Protected(v.target, false); err != nil {
			return err
		}
		if err = fresh.Unused(v.target, true); err != nil {
			return err
		}
		if err = pin.Verify(); err != nil {
			return err
		}
		parent, err := os.Open(filepath.Join(s.sys, filepath.Base(v.target)))
		if err != nil {
			return err
		}
		defer parent.Close()
		read := func(name string) (string, error) {
			fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return "", err
			}
			f := os.NewFile(uintptr(fd), name)
			defer f.Close()
			data, err := io.ReadAll(io.LimitReader(f, 129))
			if len(data) > 128 {
				return "", fmt.Errorf("invalid kernel device identity")
			}
			return strings.TrimSpace(string(data)), err
		}
		dev, err := read("dev")
		if err != nil {
			return err
		}
		sequence, err := read("diskseq")
		if err != nil {
			return err
		}
		if dev != pin.Identity.DeviceNumber || sequence != pin.Identity.DiskSequence {
			return reject("The block device changed. Review a new operation plan.")
		}
		// device/delete resolves from the pinned kernel object's directory, not a
		// subsequently reused /sys/class/block name.
		fd, err := unix.Openat(int(parent.Fd()), "device/delete", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		control := os.NewFile(uintptr(fd), "device/delete")
		defer control.Close()
		if _, err = s.run(ctx, []string{"sync"}, systemops.CommandOptions{Operation: true, Reporter: r}); err != nil {
			return err
		}
		if err = pin.Verify(); err != nil {
			return err
		}
		_, err = control.WriteString("1\n")
		return err
	})
}
