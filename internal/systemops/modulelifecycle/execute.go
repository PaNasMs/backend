package modulelifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

const incompleteRecovery = "Module recovery is incomplete. Recover the recorded transaction before changing modules."

func matchesCommitIntent(expected, recorded *transaction) bool {
	if recorded == nil || recorded.orphan {
		return false
	}
	before, after := *expected, *recorded
	before.Committed, after.Committed = false, false
	a, e1 := json.Marshal(before)
	b, e2 := json.Marshal(after)
	return e1 == nil && e2 == nil && bytes.Equal(a, b)
}

func checkpoint(ctx context.Context, reporter *systemops.Reporter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if reporter != nil {
		return reporter.Checkpoint()
	}
	return nil
}
func cancellable(reporter *systemops.Reporter, allowed bool) {
	if reporter != nil {
		reporter.Cancellable(allowed)
	}
}

func (s lifecycle) recovery() recovery {
	return recovery{store: s.store, units: s.units, run: s.run, health: s.health, mounts: s.mounts}
}

func (s lifecycle) checkPlanLive(plan *prepared) error {
	current, err := s.registry()
	if err != nil {
		return err
	}
	if !registryEqual(current, plan.installed) {
		return reject("State has changed. Review a new operation plan.")
	}
	root, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		return err
	}
	defer root.Close()
	units, err := trustedDirectory(s.units, s.owner)
	if err != nil {
		return err
	}
	defer units.Close()
	for _, id := range plan.order {
		if err = s.recovery().noMounts(filepath.Join(s.root, id)); err != nil {
			return err
		}
		payload, err := directoryAt(root, id, s.owner)
		if err != nil {
			return err
		}
		unitBefore, err := snapshotAt(units, unit(id), s.owner)
		if err != nil {
			return err
		}
		if payload != plan.payloads[id].Before || !snapshotEqual(unitBefore, plan.units[id]) {
			return reject("State has changed. Review a new operation plan.")
		}
	}
	return nil
}

func (s lifecycle) stopAffected(ctx context.Context, state *transaction, reporter *systemops.Reporter) error {
	var result error
	for _, id := range state.Affected {
		if text(state.Before[id], "service") == "" && !state.Units[id].Exists {
			continue
		}
		if _, err := s.run(context.WithoutCancel(ctx), []string{"systemctl", "disable", "--now", unit(id)}, systemops.CommandOptions{Accepted: []int{0, 5}, Operation: true, Reporter: reporter}); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (s lifecycle) haltAffected(ctx context.Context, state *transaction, reporter *systemops.Reporter) error {
	var result error
	for _, id := range state.Affected {
		if text(state.Before[id], "service") == "" && text(state.After[id], "service") == "" && !state.Units[id].Exists {
			continue
		}
		if _, err := s.run(context.WithoutCancel(ctx), []string{"systemctl", "stop", unit(id)}, systemops.CommandOptions{Accepted: []int{0, 5}, Operation: true, Reporter: reporter}); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (s lifecycle) switchPayloads(plan *prepared, state *transaction) error {
	root, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		return err
	}
	defer root.Close()
	stage, err := s.transactionDirectory()
	if err != nil {
		return err
	}
	defer stage.Close()
	fd, err := unix.Openat(int(stage.Fd()), ".new", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	newRoot := os.NewFile(uintptr(fd), "new module payloads")
	defer newRoot.Close()
	for _, id := range plan.order {
		if state.After[id] != nil && plan.available[id] == nil {
			continue
		}
		before := state.Payloads[id].Before
		actual, err := directoryAt(root, id, s.owner)
		if err != nil {
			return err
		}
		if actual != before {
			return reject("Module payload changed before activation; current files were preserved")
		}
		if before.Exists {
			if err = unix.Renameat2(int(root.Fd()), id, int(stage.Fd()), "old-"+id, unix.RENAME_NOREPLACE); err != nil {
				return err
			}
			if err = stage.Sync(); err != nil {
				return err
			}
			if err = root.Sync(); err != nil {
				return err
			}
		}
		if plan.available[id] != nil {
			actual, err = directoryAt(newRoot, id, s.owner)
			if err != nil {
				return err
			}
			if !actual.Exists || actual != state.Payloads[id].Staged {
				return reject("Staged module payload changed; recorded files were preserved")
			}
			if err = unix.Renameat2(int(newRoot.Fd()), id, int(root.Fd()), id, unix.RENAME_NOREPLACE); err != nil {
				return err
			}
			if err = root.Sync(); err != nil {
				return err
			}
			if err = newRoot.Sync(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s lifecycle) writeCandidates(state *transaction) error {
	units, err := trustedDirectory(s.units, s.owner)
	if err != nil {
		return err
	}
	defer units.Close()
	for _, id := range state.Affected {
		actual, err := snapshotAt(units, unit(id), s.owner)
		if err != nil {
			return err
		}
		if !snapshotEqual(actual, state.Units[id]) && !snapshotEqual(actual, state.Candidates[id]) {
			return reject("Module service configuration changed; current files were preserved")
		}
		if err = restoreUnit(units, unit(id), state.Candidates[id], s.owner); err != nil {
			return err
		}
	}
	return nil
}

func (s lifecycle) rememberWidgets(installed Registry) error {
	dir, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		return err
	}
	defer dir.Close()
	known := Registry{}
	raw, err := readOwnedAt(dir, "catalog.json", s.owner, 8<<20)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err == nil {
		known, err = decodeRegistry(raw)
		if err != nil {
			return err
		}
	}
	for id, manifest := range installed {
		widgets := manifest["widgets"]
		if widgets == nil {
			widgets = map[string]any{}
		}
		known[id] = Manifest{"id": id, "widgets": widgets}
	}
	raw, err = json.Marshal(known)
	if err != nil {
		return err
	}
	return atomicAt(dir, "catalog.json", raw, 0644, s.owner)
}

func (s lifecycle) removeUpload(plan *prepared) {
	if plan.archive == nil {
		return
	}
	dir, err := trustedDirectory(s.uploads, s.owner)
	if err != nil {
		return
	}
	defer dir.Close()
	var opened, current unix.Stat_t
	if unix.Fstat(int(plan.archive.Fd()), &opened) != nil || unix.Fstatat(int(dir.Fd()), plan.uploadName, &current, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return
	}
	if current.Dev == opened.Dev && current.Ino == opened.Ino && current.Uid == s.owner && current.Mode&unix.S_IFMT == unix.S_IFREG && current.Nlink == 1 {
		if unix.Unlinkat(int(dir.Fd()), plan.uploadName, 0) == nil {
			_ = dir.Sync()
		}
	}
}

func (s lifecycle) execute(ctx context.Context, action string, p map[string]any, name, expected string, reporter *systemops.Reporter, authorize func() error) (result json.RawMessage, err error) {
	mutated, live, rollback := false, false, false
	var state *transaction
	var lease *maintenanceLease
	var lock, archive *os.File
	defer func() {
		if archive != nil {
			archive.Close()
		}
		if lock != nil {
			lock.Close()
		}
		if lease != nil {
			lease.file.Close()
		}
	}()
	defer func() {
		cancellable(reporter, false)
		if err != nil && rollback && state != nil {
			if restoreErr := s.recovery().restore(context.WithoutCancel(ctx), state, reporter); restoreErr != nil {
				if live {
					_ = s.haltAffected(ctx, state, reporter)
				}
				err = reject(incompleteRecovery)
			}
		}
		if err != nil && !mutated {
			err = systemops.BeforeMutation(err)
		}
	}()
	if authorize == nil || expected == "" {
		return nil, reject("Module activation authorization is missing")
	}
	if err = authorize(); err != nil {
		return nil, err
	}
	lease, err = acquireMaintenance(s.maintenance, s.owner)
	if err != nil {
		return nil, err
	}
	cancellable(reporter, true)
	lock, err = s.lock(ctx, reporter)
	if err != nil {
		return nil, err
	}
	plan, err := s.prepare(ctx, action, p, name)
	if err != nil {
		return nil, err
	}
	archive = plan.archive
	if plan.fingerprint != expected {
		return nil, reject("State has changed. Review a new operation plan.")
	}
	if err = authorize(); err != nil {
		return nil, err
	}
	if err = checkpoint(ctx, reporter); err != nil {
		return nil, err
	}
	if action == "module.recover" {
		cancellable(reporter, false)
		if err = authorize(); err != nil {
			return nil, err
		}
		state, err = s.loadTransaction()
		if err != nil {
			return nil, err
		}
		if state == nil {
			return nil, reject("No module transaction needs recovery")
		}
		if state.requiresBarrier() {
			if err = lease.critical(); err != nil {
				return nil, err
			}
		}
		if err = s.recovery().restore(ctx, state, reporter); err != nil {
			mutated = !systemops.Unchanged(err)
			if mutated {
				_ = s.haltAffected(ctx, state, reporter)
				return nil, reject(incompleteRecovery)
			}
			return nil, err
		}
		mutated = true
		return json.Marshal(map[string]any{"message": "Module transaction recovered"})
	}
	if len(plan.order) == 0 {
		return json.Marshal(map[string]any{"message": "Modules installed and enabled", "modules": []string{}, "noChanges": true})
	}
	if len(plan.packages) > 0 {
		cancellable(reporter, false)
		if err = checkpoint(ctx, reporter); err != nil {
			return nil, err
		}
		mutated = true
		argv := append([]string{"apt-get", "-y", "--no-remove", "install"}, plan.packages...)
		if _, err = s.run(ctx, argv, systemops.CommandOptions{Operation: true, Timeout: 30 * time.Minute, Reporter: reporter}); err != nil {
			return nil, err
		}
		manifests := []Manifest{}
		for _, id := range plan.order {
			m := plan.available[id]
			if m == nil {
				m = plan.installed[id]
			}
			manifests = append(manifests, m)
		}
		missing, _, verifyErr := packagePlan(ctx, manifests, s.run, s.compare)
		if verifyErr != nil {
			return nil, verifyErr
		}
		if len(missing) > 0 {
			return nil, reject("Required OS packages were not installed; module files were preserved")
		}
	}
	if err = authorize(); err != nil {
		return nil, err
	}
	if err = s.checkPlanLive(plan); err != nil {
		return nil, err
	}
	state, err = s.begin(action, plan)
	if state != nil {
		mutated = true
		rollback = true
	}
	if err != nil {
		return nil, err
	}
	cancellable(reporter, true)
	if err = checkpoint(ctx, reporter); err != nil {
		return nil, err
	}
	if err = s.extract(ctx, plan, state, reporter); err != nil {
		return nil, err
	}
	cancellable(reporter, false)
	if err = checkpoint(ctx, reporter); err != nil {
		return nil, err
	}
	if err = authorize(); err != nil {
		return nil, err
	}
	if err = lease.critical(); err != nil {
		return nil, err
	}
	for _, id := range state.Affected {
		if err = requireIdle(ctx, state.Before[id], s.health, s.run); err != nil {
			return nil, err
		}
	}
	if err = authorize(); err != nil {
		return nil, err
	}
	if err = s.recovery().checkStaging(state); err != nil {
		return nil, err
	}
	state.Phase = "switching"
	if err = s.saveTransaction(state); err != nil {
		return nil, err
	}
	gate, err := gatedRegistry(state)
	if err != nil {
		return nil, err
	}
	if err = s.saveRegistry(gate); err != nil {
		return nil, err
	}
	live = true
	ctx = context.WithoutCancel(ctx)
	if err = s.stopAffected(ctx, state, reporter); err != nil {
		return nil, err
	}
	root, openErr := trustedDirectory(s.root, s.owner)
	if openErr != nil {
		return nil, openErr
	}
	stage, openErr := s.transactionDirectory()
	if openErr != nil {
		root.Close()
		return nil, openErr
	}
	units, openErr := trustedDirectory(s.units, s.owner)
	if openErr != nil {
		root.Close()
		stage.Close()
		return nil, openErr
	}
	err = s.recovery().checkRecoveryFiles(state, root, stage, units)
	root.Close()
	stage.Close()
	units.Close()
	if err != nil {
		return nil, err
	}
	if err = s.switchPayloads(plan, state); err != nil {
		return nil, err
	}
	if err = s.writeCandidates(state); err != nil {
		return nil, err
	}
	if err = s.rememberWidgets(state.After); err != nil {
		return nil, err
	}
	current, err := s.registry()
	if err != nil {
		return nil, err
	}
	if !registryEqual(current, gate) {
		return nil, reject("Module registry changed before activation; recorded files were preserved")
	}
	if err = s.saveRegistry(state.After); err != nil {
		return nil, err
	}
	if _, err = s.run(ctx, []string{"systemctl", "daemon-reload"}, systemops.CommandOptions{Operation: true, Reporter: reporter}); err != nil {
		return nil, err
	}
	for _, id := range plan.order {
		if state.After[id] != nil && state.After[id]["enabled"] == true {
			if err = startModule(ctx, state.After[id], s.run, s.health, reporter); err != nil {
				return nil, err
			}
		}
	}
	state.Committed = true
	if err = s.saveTransaction(state); err != nil {
		loaded, readErr := s.loadTransaction()
		if readErr == nil && matchesCommitIntent(state, loaded) {
			if loaded.Committed {
				rollback = false
			} else {
				state.Committed = false
			}
		} else {
			rollback = false
			_ = s.haltAffected(ctx, state, reporter)
			err = reject(incompleteRecovery)
		}
		return nil, err
	}
	rollback = false
	if err = s.recovery().cleanup(state); err != nil {
		return nil, err
	}
	s.removeUpload(plan)
	message := map[string]string{"module.remove": "Module removed", "module.disable": "Module disabled"}[action]
	if message == "" {
		message = "Modules installed and enabled"
	}
	if action == "module.install" && state.After[plan.target]["enabled"] == false {
		message = "Module updated; remains disabled"
	}
	return json.Marshal(map[string]any{"message": message, "modules": plan.order})
}
