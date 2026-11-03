package localmounts

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/accounts"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
	"panasms.local/backend/internal/systemops/volumeaccess"
	"path/filepath"
	"sort"
	"strings"
)

func Execute(ctx context.Context, action string, p map[string]any, actor, expected string, r *systemops.Reporter) (json.RawMessage, error) {
	return defaultService().execute(ctx, action, p, actor, expected, r)
}
func (s *service) execute(ctx context.Context, action string, p map[string]any, actor, expected string, r *systemops.Reporter) (json.RawMessage, error) {
	domain, err := storagebase.DomainLock(ctx)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer domain.Close()
	initial, err := s.prepare(ctx, action, p, actor)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	paths := map[string]bool{}
	for _, identity := range initial.identities {
		for _, device := range identity.Devices {
			paths[device.Path] = true
		}
	}
	names := []string{}
	for path := range paths {
		names = append(names, path)
	}
	sort.Strings(names)
	held := []*os.File{}
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			held[i].Close()
		}
	}()
	for _, path := range names {
		lock, err := storagebase.DeviceLock(ctx, path)
		if err != nil {
			return nil, systemops.BeforeMutation(err)
		}
		held = append(held, lock)
	}
	_, release, err := accounts.LockStorageShares(ctx)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer release()
	v, err := s.prepare(ctx, action, p, actor)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if expected == "" || v.fingerprint != expected {
		return nil, systemops.BeforeMutation(reject("State has changed. Review a new operation plan."))
	}
	identity := combinedIdentity(v)
	for _, device := range identity.Devices {
		if !paths[device.Path] {
			return nil, systemops.BeforeMutation(reject("Storage dependencies changed. Review a new operation plan."))
		}
	}
	if err = storagebase.CheckPendingRoots("localmounts", v.target, identity); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	prior, _, err := readJournal(s.root, v.target, 0)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if action != "mount.detach" && prior != nil && prior.Phase == "pending" && (prior.StageIntent || prior.MountID != 0) {
		return nil, systemops.BeforeMutation(reject("A mount operation needs recovery before a new operation can start."))
	}
	priorReload, err := pendingConfiguration(prior, v.conf)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	device := storagequery.DeviceIdentity{}
	for _, entry := range identity.Devices {
		if entry.Path == v.target {
			device = entry
		}
	}
	pin, err := storagebase.PinDevice(device)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer pin.Close()
	desired, err := plannedFstab(action, v, p)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	state := &transaction{TransactionEnvelope: storagebase.TransactionEnvelope{Schema: 1, Domain: "localmounts", Action: action, Target: v.target, Identity: identity, Phase: "pending"}, Fingerprint: v.fingerprint, Point: v.point, FSType: v.fs, FstabBefore: storagebase.Hash(v.conf), FstabDesired: desired}
	if action == "disk.prepare" {
		state.ConfigRemovedUUIDs = storagebase.RemovedFstabUUIDs(v.conf, desired)
	}
	if action == "mount.detach" && prior != nil && prior.Phase == "pending" {
		state.Stage = prior.Stage
		state.StageIntent = prior.StageIntent
		state.MountID = prior.MountID
	}
	if err = ctx.Err(); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if err = archiveJournal(s.root, v.target, v.journalRevision, 0); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	save := func(t *transaction) error { return writeJournal(s.root, 0, t) }
	if err = save(state); err != nil {
		return nil, err
	}
	perform := func(name string, operation func() error) error { return step(state, name, save, operation) }
	var response map[string]any
	switch action {
	case "mount.open":
		response, err = s.open(ctx, v, p, pin, state, save, r)
		if err != nil {
			return nil, err
		}
		if state.MountID == 0 {
			desired = v.conf
		}

	case "disk.eject":
		if err = s.eject(ctx, v, pin, state, save, r); err != nil {
			return nil, err
		}
	case "mount.attach":
		if err = s.attach(ctx, v, pin, state, save, r); err != nil {
			return nil, err
		}
	case "mount.detach":
		for _, mount := range v.selected {
			m := mount
			if err = perform("unmount:"+m.Target, func() error { return storagebase.UnmountPinned(m.Target, m) }); err != nil {
				return nil, err
			}
		}
		if err = perform("private-stage-cleanup", func() error { return s.cleanupPrivateStage(v, state) }); err != nil {
			return nil, err
		}
	case "disk.prepare":
		err = perform("remove-signatures", func() error {
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
			now, err := s.identity(fresh, v.target)
			if err != nil {
				return err
			}
			before, _ := json.Marshal(v.identities[v.target])
			after, _ := json.Marshal(now)
			if string(before) != string(after) {
				return reject("The block device changed. Review a new operation plan.")
			}
			if err = pin.Verify(); err != nil {
				return err
			}
			_, err = s.run(ctx, []string{"wipefs", "--all", "--", pin.Path()}, systemops.CommandOptions{Operation: true, Reporter: r})
			return err
		})
		if err != nil {
			return nil, err
		}
		if err = perform("refresh-storage-metadata", func() error {
			if err := pin.Verify(); err != nil {
				return err
			}
			_, err := s.run(ctx, []string{"udevadm", "trigger", "--action=change", "--settle", v.target}, systemops.CommandOptions{Operation: true, Reporter: r})
			return err
		}); err != nil {
			return nil, err
		}
	case "mount.settings":
		if err = perform("create-mountpoint", func() error {
			f, err := storagebase.CreateTarget(v.point, v.witness)
			if f != nil {
				f.Close()
			}
			return err
		}); err != nil {
			return nil, err
		}
	}
	state.FstabDesired = desired
	if action == "disk.prepare" {
		fresh, err := s.load(ctx)
		if err != nil {
			return nil, err
		}
		now, err := s.identity(fresh, v.target)
		if err != nil {
			return nil, err
		}
		if !hardwareIdentityEqual(v.identities[v.target], now) {
			return nil, reject("Storage identity changed; inspect recovery before continuing")
		}
		if text(fresh.Inventory.Rows[v.target], "uuid") != "" || len(fresh.Inventory.Descendants(v.target)) != 1 {
			return nil, reject("Prepared disk metadata has not settled; inspect recovery before continuing")
		}
		if err = verifyConfigOwners(fresh, state.ConfigRemovedUUIDs, func(string) bool { return false }); err != nil {
			return nil, err
		}
		state.ConfigIdentity = now
		state.ConfigOnlyRemaining = true
		if err = save(state); err != nil {
			return nil, err
		}
	}
	if desired != v.conf || priorReload {
		if err = perform("fstab", func() error { return storagebase.WriteFstab(ctx, state.FstabBefore, state.FstabDesired, r) }); err != nil {
			return nil, err
		}
	}
	if action == "mount.settings" && !strings.HasPrefix(v.options, "ro,") {
		if err = perform("volume-access", func() error { return volumeaccess.ApplyMounted(v.point) }); err != nil {
			return nil, err
		}
	}
	state.ConfigReconciled = true
	state.ConfigResolution = "desired"
	state.ConfigWitness = storagebase.Hash(desired)
	state.FstabDesired = desired
	state.Phase = "complete"
	if err = save(state); err != nil {
		return nil, err
	}
	if response != nil {
		return json.Marshal(response)
	}
	return json.Marshal(map[string]any{"message": "Storage operation completed", "target": v.target})
}
func combinedIdentity(v *plan) storagequery.StorageIdentity {
	result := storagequery.StorageIdentity{}
	seen := map[string]bool{}
	for _, identity := range v.identities {
		result.BootID = identity.BootID
		for _, device := range identity.Devices {
			if !seen[device.Path] {
				seen[device.Path] = true
				result.Devices = append(result.Devices, device)
			}
		}
	}
	sort.Slice(result.Devices, func(i, j int) bool { return result.Devices[i].Path < result.Devices[j].Path })
	return result
}
func plannedFstab(action string, v *plan, p map[string]any) (string, error) {
	if action == "mount.open" {
		mode := text(p, "mode")
		if mode == "repair-only" {
			return v.conf, nil
		}
		if len(v.selected) > 0 && mode != "repair" {
			readOnly := mode == "readonly" || ((mode == "" || mode == "auto") && p["readOnly"] == true)
			alreadyReadOnly := strings.Contains(","+v.selected[0].Options+",", ",ro,")
			if !readOnly || alreadyReadOnly {
				return v.conf, nil
			}
		}
	}
	return desiredFstab(action, v)
}

func desiredFstab(action string, v *plan) (string, error) {
	if action == "mount.detach" || action == "disk.eject" {
		return v.conf, nil
	}
	remove := map[string]bool{}
	line := ""
	if action == "disk.prepare" {
		for path := range v.identities {
			if uuid := text(v.preflight.Inventory.Rows[path], "uuid"); uuid != "" {
				remove[uuid] = true
			}
		}
	} else {
		uuid := text(v.preflight.Inventory.Rows[v.target], "uuid")
		if strings.ContainsAny(uuid, "/ \t\r\n") {
			return "", reject("Invalid file system UUID")
		}
		remove[uuid] = true
		line = fmt.Sprintf("UUID=%s %s %s %s 0 0", uuid, storagebase.EscapeFstab(v.point), v.fs, v.options)
	}
	return storagebase.EditFstab(v.conf, remove, line, func(uuid string) (bool, error) {
		if filepath.Base(uuid) != uuid {
			return false, reject("Invalid file system UUID")
		}
		_, err := os.Stat(filepath.Join("/dev/disk/by-uuid", uuid))
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	})
}

func hardwareIdentityEqual(a, b storagequery.StorageIdentity) bool {
	if a.BootID != b.BootID || len(a.Devices) != len(b.Devices) {
		return false
	}
	for i, x := range a.Devices {
		y := b.Devices[i]
		x.UUID = ""
		x.PartUUID = ""
		y.UUID = ""
		y.PartUUID = ""
		if x != y {
			return false
		}
	}
	return true
}

func pendingConfiguration(prior *transaction, conf string) (bool, error) {
	if prior == nil || prior.Phase != "pending" || prior.FstabBefore == storagebase.Hash(prior.FstabDesired) {
		return false, nil
	}
	if prior.ConfigReconciled {
		if prior.ConfigWitness != storagebase.Hash(conf) || (prior.ConfigResolution != "before" && prior.ConfigResolution != "desired") {
			return false, reject("Storage configuration changed after recovery; inspect it before continuing")
		}
		return false, nil
	}
	if prior.Action == "disk.prepare" {
		return false, reject("Storage configuration recovery is required before another operation")
	}
	if storagebase.Hash(conf) != prior.FstabBefore && conf != prior.FstabDesired {
		return false, reject("Storage configuration changed; inspect recovery before continuing")
	}
	return true, nil
}
