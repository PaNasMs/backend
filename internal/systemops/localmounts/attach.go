package localmounts

import (
	"context"
	"io"
	"os"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/volumeaccess"
	"strings"
)

func emptyDirectory(f *os.File) error {
	names, err := f.Readdirnames(1)
	if len(names) > 0 {
		return reject("The mount point directory must be empty")
	}
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}
func (s *service) attach(ctx context.Context, v *plan, pin *storagebase.PinnedDevice, state *transaction, save func(*transaction) error, r *systemops.Reporter) error {
	target, err := storagebase.CreateTarget(v.point, v.witness)
	if err != nil {
		return err
	}
	defer target.Close()
	if err = emptyDirectory(target); err != nil {
		return err
	}
	root := "/run/panasms-local-mounts"
	if err = storagebase.SecureDirectory(root, 0, true); err != nil {
		return err
	}
	state.Stage = privateStage(v.target)
	if _, err = os.Lstat(state.Stage); err == nil {
		return reject("A private mount stage already exists. Inspect recovery before continuing.")
	} else if !os.IsNotExist(err) {
		return err
	}
	state.StageIntent = true
	if err = save(state); err != nil {
		return err
	}
	if err = os.Mkdir(state.Stage, 0700); err != nil {
		return err
	}
	if err = step(state, "stage-mount", save, func() error {
		if err := pin.Verify(); err != nil {
			return err
		}
		_, err := s.run(ctx, []string{"mount", "--no-canonicalize", "-t", v.fs, "-o", v.options, "--", pin.Path(), state.Stage}, systemops.CommandOptions{Operation: true, Reporter: r})
		return err
	}); err != nil {
		return err
	}
	mounts, err := s.mounts()
	if err != nil {
		return err
	}
	verified := false
	for _, m := range mounts {
		if m.Target == state.Stage {
			if m.Device != pin.Identity.DeviceNumber || m.Root != "/" {
				return reject("The staged mount changed")
			}
			verified = true
		}
	}
	if !verified {
		return reject("The staged mount is unavailable")
	}
	if err = storagebase.SameDirectory(target, v.point); err != nil {
		return err
	}
	// Rewind directory enumeration before the final emptiness check.
	if _, err = target.Seek(0, 0); err != nil {
		return err
	}
	if err = emptyDirectory(target); err != nil {
		return err
	}
	_, err = storagebase.AttachStaged(state.Stage, target, func(id uint64) error { state.MountID = id; return save(state) })
	if err != nil {
		return err
	}
	mounts, err = s.mounts()
	if err != nil {
		return err
	}
	verified = false
	for _, m := range mounts {
		if m.Target == v.point && m.ID == state.MountID && m.Device == pin.Identity.DeviceNumber {
			verified = true
		}
	}
	if !verified {
		return reject("The mounted volume changed; inspect recovery")
	}
	if err = os.Remove(state.Stage); err != nil {
		return err
	}
	state.StageIntent = false
	if err = save(state); err != nil {
		return err
	}
	if !strings.HasPrefix(v.options, "ro,") {
		if err = step(state, "volume-access", save, func() error { return volumeaccess.ApplyMounted(v.point) }); err != nil {
			return err
		}
	}
	return nil
}
