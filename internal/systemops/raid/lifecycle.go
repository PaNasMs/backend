package raid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/disksleep"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
)

const lifecycleRoot = storagebase.RAIDLifecycleRoot

type intent struct {
	storagebase.TransactionEnvelope
	UUID         string    `json:"uuid"`
	MetadataUUID string    `json:"metadataUuid"`
	Step         string    `json:"step"`
	Plan         *prepared `json:"plan"`
}

func intentPath(uuid string) string { return filepath.Join(lifecycleRoot, compactUUID(uuid)+".json") }

func readIntents() ([]*intent, error) {
	if err := storagebase.SecureDirectory(lifecycleRoot, 0, false); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	entries, err := os.ReadDir(lifecycleRoot)
	if err != nil {
		return nil, err
	}
	var result []*intent
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".panasms-") {
			continue
		}
		p := filepath.Join(lifecycleRoot, entry.Name())
		st, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != 0 || st.Sys().(*syscall.Stat_t).Nlink != 1 || st.Size() > 2<<20 {
			return nil, reject("Invalid RAID lifecycle journal")
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var j intent
		if err = json.Unmarshal(raw, &j); err != nil {
			return nil, err
		}
		if !uuidPattern.MatchString(j.UUID) || !uuidPattern.MatchString(j.MetadataUUID) || intentPath(j.UUID) != p || j.Plan == nil || j.Domain != "raid" || j.Schema != 1 || j.Phase != "pending" || j.Identity.BootID == "" || len(j.Identity.Devices) == 0 {
			return nil, reject("Invalid RAID lifecycle journal")
		}
		if j.Action != "raid.create" && j.Action != "raid.delete" {
			return nil, reject("Unknown RAID lifecycle operation")
		}
		if j.Action == "raid.delete" && (j.Plan.Delete == nil || j.Plan.State == nil || len(j.Plan.State.Members) == 0) || j.Action == "raid.create" && (!arrayName.MatchString(j.Plan.Target) || len(j.Plan.Paths) < 2) {
			return nil, reject("Incomplete RAID lifecycle record")
		}
		result = append(result, &j)
	}
	return result, nil
}

func (m mutation) begin(action, uuid, metadataUUID string) (*intent, error) {
	if err := storagebase.SecureDirectory(lifecycleRoot, 0, true); err != nil {
		return nil, err
	}
	target := m.p.Target
	if action == "raid.create" {
		target = m.p.Paths[0]
	}
	merged := storagequery.StorageIdentity{BootID: m.p.Identities[target].BootID}
	seen := map[string]storagequery.DeviceIdentity{}
	for _, id := range m.p.Identities {
		if id.BootID != merged.BootID {
			return nil, reject("Storage boot identity changed")
		}
		for _, dev := range id.Devices {
			if old, ok := seen[dev.Path]; ok && old != dev {
				return nil, reject("Storage identity changed during inspection")
			}
			seen[dev.Path] = dev
		}
	}
	for _, path := range sortedKeys(seen) {
		merged.Devices = append(merged.Devices, seen[path])
	}
	j := &intent{TransactionEnvelope: storagebase.TransactionEnvelope{Schema: 1, Domain: "raid", Phase: "pending", Action: action, Target: target, Identity: merged}, UUID: uuid, MetadataUUID: metadataUUID, Plan: m.p}
	if _, err := os.Lstat(intentPath(uuid)); !os.IsNotExist(err) {
		return nil, reject("Inspect the existing RAID lifecycle journal before retrying")
	}
	return j, j.save("reviewed")
}
func (j *intent) save(step string) error {
	j.Step = step
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if len(raw) > 2<<20 {
		return reject("RAID lifecycle journal is too large")
	}
	return systemops.AtomicWrite(intentPath(j.UUID), string(raw), 0600)
}
func (j *intent) finish() error {
	if err := os.Remove(intentPath(j.UUID)); err != nil {
		return err
	}
	root, err := os.Open(lifecycleRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Sync()
}
func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	s := hex.EncodeToString(raw[:])
	return strings.Join([]string{s[:8], s[8:16], s[16:24], s[24:]}, ":"), nil
}
func LifecycleReport() (json.RawMessage, error) {
	intents, err := readIntents()
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	for _, j := range intents {
		rows = append(rows, map[string]any{"action": j.Action, "target": j.Plan.Target, "uuid": j.UUID, "step": j.Step, "mountsAndShares": j.Plan.Delete})
	}
	return json.Marshal(rows)
}

// Recovery is an explicit root operation. Boot never repeats a stop, wipe, or create.
func FinishLifecycle(ctx context.Context, uuid string) error {
	if !uuidPattern.MatchString(uuid) {
		return reject("Invalid RAID UUID")
	}
	lock, err := storagebase.DomainLock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	return disksleep.WithStorageLock(func() error {
		js, err := readIntents()
		if err != nil {
			return err
		}
		for _, j := range js {
			if compactUUID(j.UUID) != compactUUID(uuid) {
				continue
			}
			boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(boot)) != j.Identity.BootID {
				return reject("Device identities have changed across reboot. Inspect the retained RAID journal and members before manual recovery.")
			}
			paths := sortedKeys(j.Plan.Identities)
			for _, path := range paths {
				f, err := storagebase.DeviceLock(ctx, path)
				if err != nil {
					return err
				}
				defer f.Close()
			}
			m := mutation{s: defaultService(), p: j.Plan, ctx: ctx, opts: systemops.CommandOptions{Operation: true}}
			if j.Action == "raid.create" {
				if j.Step != "register" {
					return reject("Creation was interrupted before safe registration. Inspect the named array and its signatures before manual recovery.")
				}
				return m.register(j)
			}
			if j.Step != "before-stop" && j.Step != "stopped" {
				return reject("Deletion stopped before array cleanup. Inspect the journal for reviewed shares and mounts before manual recovery.")
			}
			if _, err := os.Stat(filepath.Join(m.s.sys, filepath.Base(j.Plan.Target), "md")); !os.IsNotExist(err) {
				return reject("The array is active or its state is unknown; inspect before cleanup")
			}
			return m.finishDelete(j)
		}
		return reject("No pending RAID lifecycle record for this UUID")
	})
}
func (j *intent) blocks(uuid string) bool {
	return j.Action == "raid.delete" && compactUUID(j.UUID) == compactUUID(uuid)
}
func checkIntentOverlap(p *prepared) error {
	records, err := readIntents()
	if err != nil {
		return err
	}
	for _, j := range records {
		if p.Target == j.Plan.Target {
			return reject(fmt.Sprintf("Unfinished %s on %s. Inspect RAID lifecycle journal %s.", j.Action, j.Plan.Target, j.UUID))
		}
		for _, id := range p.Identities {
			for _, d := range id.Devices {
				if slices.ContainsFunc(j.Identity.Devices, func(old storagequery.DeviceIdentity) bool {
					return old.Path == d.Path || old.DeviceNumber == d.DeviceNumber
				}) {
					return reject("Storage belongs to an unfinished RAID operation. Inspect the RAID lifecycle journal.")
				}
			}
		}
	}
	return nil
}
