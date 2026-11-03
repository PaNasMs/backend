package modulelifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

type recovery struct {
	store
	units  string
	run    command
	health healthCheck
	mounts func() ([]string, error)
}

func (r recovery) noMounts(path string) error {
	rows, err := r.mounts()
	if err != nil {
		return err
	}
	for _, mounted := range rows {
		if mounted == path || strings.HasPrefix(mounted, path+"/") {
			return reject("Module files contain mounted data; unmount it before recovery")
		}
	}
	return nil
}

func (r recovery) removeTree(path string) error {
	if filepath.Dir(path) != r.root && path != filepath.Join(r.root, ".transaction") {
		return reject("Invalid module cleanup path")
	}
	if err := r.noMounts(path); err != nil {
		return err
	}
	directory, err := trustedDirectory(path, r.owner)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	directory.Close()
	return os.RemoveAll(path)
}

func recoveryOrder(before Registry, affected []string) ([]string, error) {
	selected := map[string]bool{}
	for _, id := range affected {
		selected[id] = true
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	order := []string{}
	var visit func(string) error
	visit = func(id string) error {
		if visited[id] || before[id] == nil {
			return nil
		}
		if visiting[id] {
			return reject("Module recovery dependencies contain a cycle")
		}
		visiting[id] = true
		deps, err := dependencies(before[id])
		if err != nil {
			return err
		}
		for _, dependency := range names(deps) {
			if before[dependency] == nil {
				return reject("Missing recovery dependency: " + dependency)
			}
			if selected[dependency] {
				if err = visit(dependency); err != nil {
					return err
				}
			}
		}
		visiting[id] = false
		visited[id] = true
		order = append(order, id)
		return nil
	}
	for _, id := range names(selected) {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	return order, nil
}

func registryEqual(left, right Registry) bool {
	a, errA := json.Marshal(left)
	b, errB := json.Marshal(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

func snapshotEqual(left, right fileSnapshot) bool {
	return left.Exists == right.Exists && bytes.Equal(left.Data, right.Data) && left.Mode == right.Mode && left.UID == right.UID && left.GID == right.GID
}

func gatedRegistry(state *transaction) (Registry, error) {
	gate, err := copyRegistry(state.Before)
	if err != nil {
		return nil, err
	}
	for _, id := range state.Affected {
		if gate[id] != nil {
			gate[id]["enabled"] = false
		}
	}
	return gate, nil
}

func (r recovery) checkRecoveryFiles(state *transaction, root, staging, units *os.File) error {
	if err := r.noMounts(filepath.Join(r.root, ".transaction")); err != nil {
		return err
	}
	for _, id := range state.Affected {
		if err := r.noMounts(filepath.Join(r.root, id)); err != nil {
			return err
		}
		current, err := directoryAt(root, id, r.owner)
		if err != nil {
			return err
		}
		backup, err := directoryAt(staging, "old-"+id, r.owner)
		if err != nil {
			return err
		}
		if state.Schema == 0 {
			if backup.Exists && contains(state.Affected, "old-"+id) {
				return reject("Legacy module staging conflicts with a backup name; preserve the transaction for manual recovery")
			}
			continue
		}
		expected := state.Payloads[id]
		if backup.Exists {
			if backup != expected.Before || current.Exists && current != expected.Staged {
				return reject("Module payload changed after interruption; recorded files were preserved")
			}
		} else if expected.Before.Exists {
			if current != expected.Before {
				return reject("Original module payload is missing; recorded files were preserved")
			}
		} else if current.Exists && current != expected.Staged {
			return reject("Module payload changed after interruption; recorded files were preserved")
		}
		actualUnit, err := snapshotAt(units, unit(id), r.owner)
		if err != nil {
			return err
		}
		if !snapshotEqual(actualUnit, state.Units[id]) && !snapshotEqual(actualUnit, state.Candidates[id]) {
			return reject("Module service configuration changed; current files were preserved")
		}
	}
	if state.Schema == 1 {
		current, err := r.registry()
		if err != nil {
			return err
		}
		gate, err := gatedRegistry(state)
		if err != nil {
			return err
		}
		if !registryEqual(current, state.Before) && !registryEqual(current, gate) && !registryEqual(current, state.After) {
			return reject("Module registry changed after interruption; current files were preserved")
		}
	}
	return nil
}

func restoreUnit(directory *os.File, name string, snapshot fileSnapshot, owner uint32) error {
	if snapshot.Exists {
		return atomicOwnedAt(directory, name, snapshot.Data, snapshot.Mode, owner, snapshot.GID)
	}
	if err := unix.Unlinkat(int(directory.Fd()), name, 0); err != nil && err != unix.ENOENT {
		return err
	}
	return directory.Sync()
}

func (r recovery) checkStaging(state *transaction) error {
	root, err := trustedDirectory(r.root, r.owner)
	if err != nil {
		return err
	}
	defer root.Close()
	stage, err := r.transactionDirectory()
	if err != nil {
		return err
	}
	defer stage.Close()
	units, err := trustedDirectory(r.units, r.owner)
	if err != nil {
		return err
	}
	defer units.Close()
	for _, id := range state.Affected {
		current, err := directoryAt(root, id, r.owner)
		if err != nil {
			return err
		}
		backup, err := directoryAt(stage, "old-"+id, r.owner)
		if err != nil {
			return err
		}
		currentUnit, err := snapshotAt(units, unit(id), r.owner)
		if err != nil {
			return err
		}
		if current != state.Payloads[id].Before || backup.Exists || !snapshotEqual(currentUnit, state.Units[id]) {
			return reject("Installed modules changed while staging; recorded files were preserved")
		}
	}
	current, err := r.registry()
	if err != nil {
		return err
	}
	if !registryEqual(current, state.Before) {
		return reject("Module registry changed while staging; recorded files were preserved")
	}
	return nil
}

// Live restoration requires both lifecycle EX and maintenance EX. Verified
// staging or committed-backup cleanup only needs the shared maintenance lease.
func (r recovery) restore(ctx context.Context, state *transaction, reporter *systemops.Reporter) (err error) {
	mutated := false
	defer func() {
		if err != nil && !mutated {
			err = systemops.BeforeMutation(err)
		}
	}()
	if state.orphan {
		current, err := r.loadTransaction()
		if err != nil {
			return err
		}
		if current == nil || !current.orphan || current.orphanFingerprint != state.orphanFingerprint {
			return reject("Module transaction changed; recorded files were preserved")
		}
		mutated = true
		return r.cleanup(state, false)
	}
	if err := state.validate(r.owner); err != nil {
		return err
	}
	stagingPath := filepath.Join(r.root, ".transaction")
	if state.Schema == 1 && state.Phase == "staging" {
		if err := r.checkStaging(state); err != nil {
			return err
		}
		mutated = true
		return r.cleanup(state, false)
	}
	if state.Committed {
		mutated = true
		return r.cleanup(state, false)
	}
	order, err := recoveryOrder(state.Before, state.Affected)
	if err != nil {
		return err
	}
	root, err := trustedDirectory(r.root, r.owner)
	if err != nil {
		return err
	}
	defer root.Close()
	staging, err := r.transactionDirectory()
	if err != nil {
		return err
	}
	defer staging.Close()
	units, err := trustedDirectory(r.units, r.owner)
	if err != nil {
		return err
	}
	defer units.Close()
	if err = r.checkRecoveryFiles(state, root, staging, units); err != nil {
		return err
	}
	ctx = context.WithoutCancel(ctx)
	mutated = true
	for _, id := range state.Affected {
		if state.Schema == 1 && text(state.Before[id], "service") == "" && text(state.After[id], "service") == "" && !state.Units[id].Exists {
			continue
		}
		if _, err = r.run(ctx, []string{"systemctl", "disable", "--now", unit(id)}, systemops.CommandOptions{Accepted: []int{0, 5}, Operation: true, Reporter: reporter}); err != nil {
			return err
		}
	}
	for _, id := range state.Affected {
		backup, err := directoryAt(staging, "old-"+id, r.owner)
		if err != nil {
			return err
		}
		if backup.Exists {
			if err = r.removeTree(filepath.Join(r.root, id)); err != nil {
				return err
			}
			if err = unix.Renameat(int(staging.Fd()), "old-"+id, int(root.Fd()), id); err != nil {
				return err
			}
			if err = staging.Sync(); err != nil {
				return err
			}
			if err = root.Sync(); err != nil {
				return err
			}
		} else if state.Before[id] == nil {
			if err = r.removeTree(filepath.Join(r.root, id)); err != nil {
				return err
			}
			if err = root.Sync(); err != nil {
				return err
			}
		}
	}
	for _, id := range state.Affected {
		if state.Schema == 1 {
			if err = restoreUnit(units, unit(id), state.Units[id], r.owner); err != nil {
				return err
			}
		} else if manifest := state.Before[id]; manifest != nil && text(manifest, "service") != "" {
			if err = writeUnit(r.root, r.units, manifest, r.owner); err != nil {
				return err
			}
		} else if state.Before[id] == nil {
			if err = restoreUnit(units, unit(id), fileSnapshot{}, r.owner); err != nil {
				return err
			}
		}
	}
	if err = r.saveRegistry(state.Before); err != nil {
		return err
	}
	if _, err = r.run(ctx, []string{"systemctl", "daemon-reload"}, systemops.CommandOptions{Operation: true, Reporter: reporter}); err != nil {
		return err
	}
	for _, id := range order {
		if state.Before[id]["enabled"] == true {
			if err = startModule(ctx, state.Before[id], r.run, r.health, reporter); err != nil {
				return err
			}
		}
	}
	if err = r.noMounts(stagingPath); err != nil {
		return err
	}
	return r.cleanup(state, true)
}

func (r recovery) cleanup(state *transaction, priorMutation bool) (err error) {
	mutated := priorMutation
	defer func() {
		if err != nil && !mutated {
			err = systemops.BeforeMutation(err)
		}
	}()
	if err := r.noMounts(filepath.Join(r.root, ".transaction")); err != nil {
		return err
	}
	if state.Schema == 1 && state.Committed {
		dir, err := r.transactionDirectory()
		if err != nil {
			return err
		}
		defer dir.Close()
		for _, id := range state.Affected {
			backup, err := directoryAt(dir, "old-"+id, r.owner)
			if err != nil {
				return err
			}
			if backup.Exists && backup != state.Payloads[id].Before {
				return reject("Module backup changed; recorded files were preserved")
			}
		}
	}
	path := filepath.Join(r.root, ".transaction")
	directory, err := trustedDirectory(path, r.owner)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	directory.Close()
	mutated = true
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	dir, err := trustedDirectory(r.root, r.owner)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
