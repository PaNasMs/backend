package snapshots

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/accounts"
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagebase"
)

const (
	createAction  = "filesystem.snapshot-create"
	deleteAction  = "filesystem.snapshot-delete"
	restoreAction = "filesystem.snapshot-restore"
)

func IsAction(action string) bool {
	return action == createAction || action == deleteAction || action == restoreAction
}

type operation struct {
	volume                       *volume
	source                       *os.File
	sourceInfo                   subvolumeInfo
	label, snapshot, fingerprint string
	details                      []string
}

func (op *operation) close() {
	if op.source != nil {
		op.source.Close()
	}
	op.volume.Close()
}

func requireAbsent(dir *os.File, label string) error {
	if dir == nil {
		return nil
	}
	var stat unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), label, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err == nil {
		return reject("Name already in use")
	}
	return err
}

func inside(path, root string) bool {
	return path == root || strings.HasPrefix(path, strings.TrimSuffix(root, "/")+"/")
}

func checkUse(v *volume, snapshot string, shares []accounts.StorageShare) error {
	path := filepath.Join(v.Point, directoryName, snapshot)
	rel := filepath.Join(v.Mount.Root, directoryName, snapshot)
	rows, err := folders.ReadMounts()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if inside(row.Target, path) {
			return reject("Unmount the snapshot before deleting or restoring it")
		}
		if row.ID == v.Mount.ID || row.FSType != "btrfs" {
			continue
		}
		// A bind of the snapshot, a descendant, or its parent can expose this
		// same tree under an unrelated mountpoint, with a different mount ID.
		if !inside(row.Root, rel) && !inside(rel, row.Root) {
			continue
		}
		source, err := filepath.EvalSymlinks(row.Source)
		if err != nil {
			return reject("Could not verify the Btrfs mount source")
		}
		for _, member := range v.members {
			if source == member {
				return reject("Unmount the snapshot before deleting or restoring it")
			}
		}
	}
	exports, err := storagebase.ActiveNFSExports()
	if err != nil {
		return err
	}
	for _, share := range shares {
		exports = append(exports, share.Path)
	}
	for _, shared := range exports {
		used, err := storagebase.ConfiguredInside(shared, path)
		if err != nil {
			return err
		}
		if used {
			return reject("Remove the snapshot share before deleting or restoring it")
		}
	}
	return nil
}

func prepare(ctx context.Context, action string, params map[string]any, shares []accounts.StorageShare) (*operation, error) {
	if !IsAction(action) {
		return nil, systemops.ErrNoRoute
	}
	target, _ := params["target"].(string)
	v, err := loadVolume(ctx, target)
	if err != nil {
		return nil, err
	}
	op := &operation{volume: v}
	keep := false
	defer func() {
		if !keep {
			op.close()
		}
	}()
	if err = storagebase.CheckPendingRoots("snapshots", v.Target, v.Identity); err != nil {
		return nil, err
	}
	if action != deleteAction {
		name, _ := params["name"].(string)
		op.label, err = systemops.Name(name)
		if err != nil {
			return nil, err
		}
		dest := v.Root
		if action == createAction {
			dest = v.Directory
		}
		if err = requireAbsent(dest, op.label); err != nil {
			return nil, err
		}
	}
	if action != createAction {
		name, _ := params["snapshot"].(string)
		op.snapshot, err = systemops.Name(name)
		if err != nil {
			return nil, err
		}
		op.source, op.sourceInfo, err = v.snapshot(op.snapshot)
		if err != nil {
			return nil, err
		}
		if err = checkUse(v, op.snapshot, shares); err != nil {
			return nil, err
		}
	}
	path := filepath.Join(v.Point, directoryName, op.snapshot)
	switch action {
	case createAction:
		op.details = []string{v.Target, op.label, "The snapshot is read-only. Nested subvolumes are not included. A snapshot is not a backup against disk failure."}
	case deleteAction:
		op.details = []string{path, "This snapshot will be deleted. The current files will be preserved."}
	case restoreAction:
		op.details = []string{path, filepath.Join(v.Point, op.label), "A writable copy will be restored in a new folder. Current files will not be replaced."}
	}
	var dirWitness any
	if v.Directory != nil {
		var st unix.Stat_t
		if err = unix.Fstat(int(v.Directory.Fd()), &st); err != nil {
			return nil, err
		}
		dirWitness = [2]uint64{uint64(st.Dev), st.Ino}
	}
	// Exclude the live root generation: normal writes are what a new snapshot captures.
	raw, err := json.Marshal(map[string]any{"device": v.Identity, "mount": v.Mount, "rootID": v.RootInfo.ID, "rootUUID": v.RootInfo.UUID, "store": dirWitness, "snapshot": op.sourceInfo})
	if err != nil {
		return nil, err
	}
	var state any
	if err = systemops.Decode(raw, &state); err != nil {
		return nil, err
	}
	op.fingerprint, err = systemops.Fingerprint(action, params, state)
	if err != nil {
		return nil, err
	}
	keep = true
	return op, nil
}

func Plan(ctx context.Context, action string, params map[string]any) (json.RawMessage, error) {
	lock, err := storagebase.DomainLock(ctx)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	var shares []accounts.StorageShare
	if action != createAction {
		shares, err = accounts.StorageShares()
		if err != nil {
			return nil, err
		}
	}
	op, err := prepare(ctx, action, params, shares)
	if err != nil {
		return nil, err
	}
	defer op.close()
	return json.Marshal(map[string]any{"target": op.volume.Target, "confirmation": op.volume.Target, "details": op.details, "fingerprint": op.fingerprint})
}

func Execute(ctx context.Context, action string, params map[string]any, expected string, authorize func() error, r *systemops.Reporter) (json.RawMessage, error) {
	domain, err := storagebase.DomainLock(ctx)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer domain.Close()
	input, _ := params["target"].(string)
	target, err := storagebase.RecoveryTarget(input)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	lock, err := storagebase.DeviceLock(ctx, target)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer lock.Close()
	var shares []accounts.StorageShare
	if action != createAction {
		var unlock func()
		shares, unlock, err = accounts.LockStorageShares(ctx)
		if err != nil {
			return nil, systemops.BeforeMutation(err)
		}
		defer unlock()
	}
	op, err := prepare(ctx, action, params, shares)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer op.close()
	v := op.volume
	if target != v.Target || expected == "" || op.fingerprint != expected {
		return nil, systemops.BeforeMutation(reject("State has changed. Review a new operation plan."))
	}
	if authorize == nil {
		return nil, systemops.BeforeMutation(reject("Account authorization is unavailable"))
	}
	if err = authorize(); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if err = v.verify(); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if action != createAction {
		f, info, err := v.snapshot(op.snapshot)
		if err != nil {
			return nil, systemops.BeforeMutation(err)
		}
		f.Close()
		if info != op.sourceInfo {
			return nil, systemops.BeforeMutation(reject("The snapshot changed. Review a new operation plan."))
		}
		if err = checkUse(v, op.snapshot, shares); err != nil {
			return nil, systemops.BeforeMutation(err)
		}
	}
	if r != nil {
		r.Cancellable(false)
		if err = r.Checkpoint(); err != nil {
			return nil, systemops.BeforeMutation(err)
		}
		r.Stage("Updating Btrfs subvolumes")
	}
	if err = ctx.Err(); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if err = op.apply(action); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"target": v.Target, "message": "Operation complete."})
}

// btrfs_ioctl_vol_args_v2 from linux/btrfs.h, shared by the create and delete requests.
type volumeArgs struct {
	FD             int64
	TransID, Flags uint64
	Reserved       [4]uint64
	Name           [4040]byte
}

const (
	snapshotCreateV2  = 0x50009417
	snapshotDestroyV2 = 0x5000943f
	btrfsSync         = 0x9408
	readOnly          = 2
)

func (op *operation) apply(action string) error {
	v := op.volume
	dest := v.Directory
	source := v.Root
	name := op.label
	var args volumeArgs
	request := uintptr(snapshotCreateV2)
	switch action {
	case createAction:
		args.Flags = readOnly
		if dest == nil {
			if err := unix.Mkdirat(int(v.Root.Fd()), directoryName, 0700); err != nil {
				return systemops.BeforeMutation(err)
			}
			var err error
			dest, err = v.openDirectory()
			if err != nil {
				return err
			}
			v.Directory = dest
			if err = v.verify(); err != nil {
				return err
			}
		}
	case restoreAction:
		dest, source = v.Root, op.source
	case deleteAction:
		// A by-ID deletion can follow a moved subvolume outside its managed store.
		// By-name lookup is anchored to the checked root-only parent directory.
		request = snapshotDestroyV2
		name = op.snapshot
	}
	if action != deleteAction {
		args.FD = int64(source.Fd())
	}
	copy(args.Name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, dest.Fd(), request, uintptr(unsafe.Pointer(&args)))
	runtime.KeepAlive(source)
	runtime.KeepAlive(dest)
	if errno != 0 {
		return reject("Btrfs snapshot operation failed: " + errno.Error() + ". Inspect the volume before retrying.")
	}
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, v.Root.Fd(), btrfsSync, 0)
	runtime.KeepAlive(v.Root)
	if errno != 0 {
		return reject("Could not confirm the Btrfs transaction commit. Inspect the volume before retrying.")
	}
	return nil
}

func Recovery(ctx context.Context, target string, params map[string]any) (json.RawMessage, error) {
	checks := []map[string]any{{"label": "Target", "value": target}}
	v, err := loadVolume(ctx, target)
	if err != nil {
		checks = append(checks, map[string]any{"label": "Btrfs volume", "value": "Unavailable. Check the device and its mount."})
	} else {
		defer v.Close()
		checks = append(checks, map[string]any{"label": "Mount point", "value": v.Point})
		for _, field := range []string{"snapshot", "name"} {
			input, _ := params[field].(string)
			label, e := systemops.Name(input)
			if e != nil {
				continue
			}
			for _, entry := range []struct {
				dir   *os.File
				point string
			}{{v.Directory, filepath.Join(v.Point, directoryName)}, {v.Root, v.Point}} {
				state := "Absent"
				if entry.dir != nil {
					var stat unix.Stat_t
					e := unix.Fstatat(int(entry.dir.Fd()), label, &stat, unix.AT_SYMLINK_NOFOLLOW)
					switch {
					case e == nil:
						state = "Present"
					case !errors.Is(e, unix.ENOENT):
						state = "Unavailable"
					}
				}
				checks = append(checks, map[string]any{"label": filepath.Join(entry.point, label), "value": state})
			}
		}
	}
	return json.Marshal(map[string]any{"message": "Inspect the snapshot and any restored folder before preparing a new operation. The interrupted operation has not been repeated.", "checks": checks, "route": "/storage/mounts", "recoveryAction": nil})
}
