package storagebase

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagequery"
)

// A sound record can become impossible to apply without changing foreign state.
// Keep these refusals distinct from gaps in evidence, invalid records and I/O failures.
type configConflict struct{ cause error }

func (e *configConflict) Error() string       { return e.cause.Error() }
func (e *configConflict) Unwrap() error       { return e.cause }
func conflict(message string) error           { return &configConflict{reject(message)} }
func IsConfigRecoveryConflict(err error) bool { var c *configConflict; return errors.As(err, &c) }

type configRecord struct {
	TransactionEnvelope
	ConfigRecovery
	FstabBefore  string `json:"fstabBefore"`
	FstabDesired string `json:"fstabDesired"`
	Steps        []struct {
		Name      string `json:"name"`
		Completed bool   `json:"completed"`
	} `json:"steps"`
	StageIntent bool   `json:"stageIntent"`
	MountID     uint64 `json:"mountID"`
	Stage       string `json:"stage"`
}
type configRecoveryService struct {
	roots       []PendingRoot
	owner       int
	preflight   func(context.Context) (*storagequery.Preflight, error)
	identity    func(*storagequery.Preflight, string) (storagequery.StorageIdentity, error)
	readConfig  func() (string, error)
	writeConfig func(context.Context, string, string, *systemops.Reporter) error
	write       func(string, string, os.FileMode) error
}
type configRecoveryPlan struct {
	record                                                       configRecord
	fields                                                       map[string]json.RawMessage
	path, journalHash, current, desired, resolution, fingerprint string
	identity                                                     storagequery.StorageIdentity
	raw                                                          json.RawMessage
}

func defaultConfigRecovery() *configRecoveryService {
	return &configRecoveryService{roots: TransactionRoots, owner: 0, preflight: storagequery.LoadPreflight, identity: func(p *storagequery.Preflight, target string) (storagequery.StorageIdentity, error) {
		return p.Identity(target)
	}, readConfig: ReadFstab, writeConfig: WriteFstab, write: systemops.AtomicWrite}
}
func ConfigRecoveryPlan(ctx context.Context, params map[string]any) (json.RawMessage, error) {
	lock, err := DomainLock(ctx)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	return ConfigRecoveryPlanLocked(ctx, params)
}

// ConfigRecoveryPlanLocked inspects ordinary recovery while the caller owns DomainLock.
func ConfigRecoveryPlanLocked(ctx context.Context, params map[string]any) (json.RawMessage, error) {
	target, _ := params["target"].(string)
	plan, err := defaultConfigRecovery().prepare(ctx, target)
	if err != nil {
		return nil, err
	}
	return plan.raw, nil
}
func ConfigRecoveryExecute(ctx context.Context, params map[string]any, expected string, r *systemops.Reporter) (json.RawMessage, error) {
	lock, err := DomainLock(ctx)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer lock.Close()
	target, _ := params["target"].(string)
	s := defaultConfigRecovery()
	plan, err := s.prepare(ctx, target)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	paths := []string{}
	for _, d := range plan.identity.Devices {
		paths = append(paths, d.Path)
	}
	sort.Strings(paths)
	locks := []*os.File{}
	defer func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].Close()
		}
	}()
	for _, path := range paths {
		l, e := DeviceLock(ctx, path)
		if e != nil {
			return nil, systemops.BeforeMutation(e)
		}
		locks = append(locks, l)
	}
	fresh, err := s.prepare(ctx, target)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if expected == "" || expected != fresh.fingerprint || fresh.fingerprint != plan.fingerprint {
		return nil, systemops.BeforeMutation(reject("State has changed. Review a new operation plan."))
	}
	return s.execute(ctx, fresh, r)
}
func (s *configRecoveryService) read(root PendingRoot, target string) (*configRecoveryPlan, error) {
	if err := SecureDirectory(root.Path, s.owner, false); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	path := filepath.Join(root.Path, Hash(target)+".json")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || int(stat.Uid) != s.owner || stat.Nlink != 1 {
		return nil, reject("Storage recovery record permissions are unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 2<<20 {
		return nil, reject("Storage recovery record is too large")
	}
	p := &configRecoveryPlan{path: path, journalHash: Hash(string(data))}
	if err = json.Unmarshal(data, &p.record); err != nil {
		return nil, reject("Storage recovery record is invalid")
	}
	if err = json.Unmarshal(data, &p.fields); err != nil || p.fields == nil {
		return nil, reject("Storage recovery record is invalid")
	}
	a := p.record
	allowed := a.Domain == "partitionfs" && (a.Action == "partition.delete" || a.Action == "filesystem.format" || a.Action == "filesystem.remove") || a.Domain == "localmounts" && a.Action == "disk.prepare"
	if a.Schema != 1 || a.Domain != root.Domain || a.Target != target || (a.Phase != "pending" && a.Phase != "complete") || len(a.FstabBefore) != 64 || a.Identity.BootID == "" || len(a.Identity.Devices) == 0 {
		return nil, reject("Storage configuration recovery is unavailable for this record")
	}
	if a.Phase == "complete" {
		return nil, nil
	}
	if !allowed {
		return nil, reject("Storage configuration recovery is unavailable for this record")
	}
	return p, nil
}
func sameHardware(old, now storagequery.DeviceIdentity) bool {
	return old.Path == now.Path && old.DeviceNumber == now.DeviceNumber && old.DiskSequence == now.DiskSequence && old.WWN == now.WWN && old.Serial == now.Serial
}
func (s *configRecoveryService) prepare(ctx context.Context, target string) (*configRecoveryPlan, error) {
	resolved, resolveErr := RecoveryTarget(target)
	if resolveErr != nil {
		return nil, resolveErr
	}
	target = resolved
	var plan *configRecoveryPlan
	for _, root := range s.roots {
		p, err := s.read(root, target)
		if err != nil {
			return nil, err
		}
		if p != nil {
			if plan != nil {
				return nil, reject("Storage recovery evidence is ambiguous")
			}
			plan = p
		}
	}
	if plan == nil {
		return nil, reject("No pending storage configuration recovery was found")
	}
	record := plan.record
	current, err := s.readConfig()
	if err != nil {
		return nil, err
	}
	if Hash(current) != record.FstabBefore && current != record.FstabDesired {
		return nil, conflict("Storage configuration changed; review recovery before modifying it")
	}
	p, err := s.preflight(ctx)
	if err != nil {
		return nil, err
	}
	witness := record.Identity
	if record.ConfigOnlyRemaining {
		witness = record.ConfigIdentity
	}
	if witness.BootID == "" || witness.BootID != record.Identity.BootID || len(witness.Devices) == 0 {
		return nil, reject("Storage recovery identity is unavailable")
	}
	original := map[string]storagequery.DeviceIdentity{}
	for _, d := range record.Identity.Devices {
		original[d.Path] = d
	}
	targetPresent := p.Inventory.Rows[target] != nil
	if targetPresent {
		if err = p.Protected(target, false); err != nil {
			return nil, err
		}
	}
	observed := storagequery.StorageIdentity{BootID: witness.BootID, Devices: []storagequery.DeviceIdentity{}}
	for _, d := range witness.Devices {
		before, ok := original[d.Path]
		if !ok || !sameHardware(before, d) {
			return nil, conflict("Storage recovery identity changed")
		}
		if p.Inventory.Rows[d.Path] == nil {
			return nil, conflict("Storage recovery identity changed")
		}
		now, e := s.identity(p, d.Path)
		if e != nil {
			return nil, e
		}
		if now.BootID != witness.BootID {
			return nil, conflict("Storage recovery identity changed")
		}
		for _, live := range now.Devices {
			known := false
			for _, saved := range witness.Devices {
				if sameHardware(saved, live) {
					known = true
					break
				}
			}
			if !known {
				return nil, conflict("Storage recovery identity changed")
			}
		}
		found := false
		for _, live := range now.Devices {
			if live.Path == d.Path {
				if !sameHardware(d, live) {
					return nil, conflict("Storage recovery identity changed")
				}
				observed.Devices = append(observed.Devices, live)
				found = true
			}
		}
		if !found {
			return nil, conflict("Storage recovery identity changed")
		}
	}
	if !targetPresent && (!record.ConfigOnlyRemaining || record.Action != "partition.delete") {
		return nil, conflict("Storage recovery identity changed")
	}
	if err = checkPendingRoots(s.roots, s.owner, record.Domain, target, observed); err != nil {
		return nil, err
	}
	oldUUIDs := map[string]bool{}
	for _, d := range record.Identity.Devices {
		if d.UUID != "" {
			oldUUIDs[d.UUID] = true
		}
	}
	removed := map[string]bool{}
	for _, uuid := range record.ConfigRemovedUUIDs {
		if uuid == "" || !oldUUIDs[uuid] || removed[uuid] {
			return nil, reject("Storage recovery configuration intent is invalid")
		}
		removed[uuid] = true
	}
	if Hash(current) == record.FstabBefore {
		expected := current
		if len(removed) > 0 {
			var e error
			expected, e = EditFstab(current, removed, "", nil)
			if e != nil {
				return nil, e
			}
		}
		if expected != record.FstabDesired {
			return nil, reject("Storage recovery configuration intent is invalid")
		}
	}
	anyLive := false
	for _, row := range p.Inventory.Rows {
		uuid, _ := row["uuid"].(string)
		if removed[uuid] {
			anyLive = true
		}
	}
	resolution, desired := "desired", record.FstabDesired
	if anyLive {
		if record.ConfigOnlyRemaining || Hash(current) != record.FstabBefore {
			return nil, conflict("The original file system is still present; preserve its configuration")
		}
		for _, d := range record.Identity.Devices {
			if removed[d.UUID] {
				row := p.Inventory.Rows[d.Path]
				if row == nil || row["uuid"] != d.UUID {
					return nil, conflict("Storage recovery identity changed")
				}
			}
		}
		resolution, desired = "before", current
	}
	plan.current, plan.desired, plan.resolution, plan.identity = current, desired, resolution, observed
	stateBytes, err := json.Marshal(map[string]any{"journal": plan.journalHash, "configuration": Hash(current), "identity": observed, "resolution": resolution})
	if err != nil {
		return nil, err
	}
	var fingerprintState map[string]any
	if err = systemops.Decode(stateBytes, &fingerprintState); err != nil {
		return nil, err
	}
	plan.fingerprint, err = systemops.Fingerprint("storage.recover", map[string]any{"target": target}, fingerprintState)
	if err != nil {
		return nil, err
	}
	details := []string{"Only saved mount configuration will be reconciled. Partition and file-system writes will not be repeated."}
	if resolution == "before" {
		details = append(details, "The original file system is still present. Keep its existing mount configuration and reload it.")
	} else {
		details = append(details, "Apply the saved mount configuration and reload it, including when it is already written.")
	}
	plan.raw, err = json.Marshal(map[string]any{"target": target, "fingerprint": plan.fingerprint, "confirmation": target, "details": details})
	return plan, err
}
func configCanComplete(r configRecord) bool {
	if !r.ConfigOnlyRemaining || r.StageIntent || r.MountID != 0 || r.Stage != "" {
		return false
	}
	allowed := map[string]string{"partition.delete": "delete-partition", "filesystem.format": "format-filesystem", "filesystem.remove": "remove-filesystem", "disk.prepare": "remove-signatures"}
	required := allowed[r.Action]
	found := false
	for _, s := range r.Steps {
		if s.Name == "fstab" || s.Name == "update-fstab" {
			continue
		}
		if r.Action == "disk.prepare" && s.Name == "refresh-storage-metadata" && s.Completed {
			continue
		}
		if s.Name != required || !s.Completed {
			return false
		}
		found = true
	}
	return found
}
func (s *configRecoveryService) execute(ctx context.Context, plan *configRecoveryPlan, r *systemops.Reporter) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	// Even an already-written desired value must regenerate units before acknowledgement.
	if err := s.writeConfig(ctx, Hash(plan.current), plan.desired, r); err != nil {
		return nil, err
	}
	var root PendingRoot
	for _, candidate := range s.roots {
		if candidate.Domain == plan.record.Domain {
			root = candidate
		}
	}
	fresh, err := s.read(root, plan.record.Target)
	if err != nil {
		return nil, err
	}
	if fresh == nil || fresh.journalHash != plan.journalHash {
		return nil, reject("Storage recovery record changed; preserve it for inspection")
	}
	current, err := s.readConfig()
	if err != nil {
		return nil, err
	}
	if current != plan.desired {
		return nil, conflict("Storage configuration changed; review recovery before modifying it")
	}
	put := func(key string, value any) { data, _ := json.Marshal(value); plan.fields[key] = data }
	put("configReconciled", true)
	put("configResolution", plan.resolution)
	put("configWitness", Hash(current))
	if plan.resolution == "desired" {
		var steps []map[string]json.RawMessage
		if err = json.Unmarshal(plan.fields["steps"], &steps); err != nil {
			return nil, err
		}
		for _, step := range steps {
			var name string
			if err = json.Unmarshal(step["name"], &name); err != nil {
				return nil, err
			}
			if name == "fstab" || name == "update-fstab" {
				step["completed"] = json.RawMessage("true")
			}
		}
		put("steps", steps)
	}
	complete := plan.resolution == "desired" && configCanComplete(plan.record)
	if complete {
		put("phase", "complete")
		if _, ok := plan.fields["complete"]; ok {
			put("complete", true)
		}
	}
	data, err := json.Marshal(plan.fields)
	if err != nil {
		return nil, err
	}
	if len(data) > 2<<20 {
		return nil, reject("Storage recovery record is too large")
	}
	if err = s.write(plan.path, string(data), 0600); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"ok": true, "configurationReconciled": true, "diskStepsRepeated": false, "complete": complete})
}

func ConfigRecoveryReport(target string) (json.RawMessage, error) {
	return defaultConfigRecovery().report(target)
}
func (s *configRecoveryService) report(target string) (json.RawMessage, error) {
	resolved, resolveErr := RecoveryTarget(target)
	if resolveErr != nil {
		return nil, resolveErr
	}
	target = resolved
	var summary any
	var action any
	for _, root := range s.roots {
		plan, err := s.read(root, target)
		if err != nil {
			return nil, err
		}
		if plan == nil {
			continue
		}
		if summary != nil {
			return nil, reject("Storage recovery evidence is ambiguous")
		}
		record := plan.record
		pending := !record.ConfigReconciled && record.FstabBefore != Hash(record.FstabDesired)
		summary = map[string]any{"action": record.Action, "target": record.Target, "phase": record.Phase, "configurationPending": pending, "configurationReconciled": record.ConfigReconciled}
		if pending {
			action = "storage.recover"
		}
	}
	return json.Marshal(map[string]any{"target": target, "journal": summary, "automaticReplay": false, "recoveryAction": action})
}
