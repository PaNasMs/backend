package storagebase

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagequery"
)

func recoveryFixture(t *testing.T) (*configRecoveryService, *configRecord, *string, *int, func()) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	id := storagequery.StorageIdentity{BootID: "boot-a", Devices: []storagequery.DeviceIdentity{{Path: "/dev/loop9", DeviceNumber: "7:9", DiskSequence: "15", UUID: "old"}}}
	record := &configRecord{TransactionEnvelope: TransactionEnvelope{Schema: 1, Domain: "partitionfs", Action: "filesystem.format", Target: "/dev/loop9", Identity: id, Phase: "pending"}, ConfigRecovery: ConfigRecovery{ConfigRemovedUUIDs: []string{"old"}, ConfigOnlyRemaining: true, ConfigIdentity: id}, FstabBefore: Hash("UUID=old /data ext4 defaults 0 2\n"), FstabDesired: "\n"}
	record.Steps = append(record.Steps, struct {
		Name      string `json:"name"`
		Completed bool   `json:"completed"`
	}{"format-filesystem", true})
	current := "UUID=old /data ext4 defaults 0 2\n"
	reloads := 0
	p := &storagequery.Preflight{Inventory: &storagequery.Inventory{Rows: map[string]map[string]any{"/dev/loop9": {"uuid": "new", "type": "loop"}}}}
	s := &configRecoveryService{roots: []PendingRoot{{root, "partitionfs"}}, owner: os.Getuid(), preflight: func(context.Context) (*storagequery.Preflight, error) { return p, nil }, identity: func(*storagequery.Preflight, string) (storagequery.StorageIdentity, error) { return id, nil }, readConfig: func() (string, error) { return current, nil }, write: func(path, data string, mode os.FileMode) error { return os.WriteFile(path, []byte(data), mode) }}
	s.writeConfig = func(_ context.Context, before, desired string, _ *systemops.Reporter) error {
		if Hash(current) != before && current != desired {
			return errors.New("foreign config")
		}
		current = desired
		reloads++
		return nil
	}
	save := func() {
		t.Helper()
		b, e := json.Marshal(record)
		if e != nil {
			t.Fatal(e)
		}
		var fields map[string]any
		if e = json.Unmarshal(b, &fields); e != nil {
			t.Fatal(e)
		}
		fields["ownerEvidence"] = "preserved"
		fields["complete"] = false
		b, _ = json.Marshal(fields)
		if e = os.WriteFile(filepath.Join(root, Hash(record.Target)+".json"), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	save()
	return s, record, &current, &reloads, save
}
func TestConfigRecoveryDesiredReloadAndPreservedFields(t *testing.T) {
	s, record, current, reloads, _ := recoveryFixture(t)
	plan, e := s.prepare(context.Background(), record.Target)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.execute(context.Background(), plan, nil); e != nil {
		t.Fatal(e)
	}
	if *current != record.FstabDesired || *reloads != 1 {
		t.Fatal("configuration/reload missing")
	}
	b, e := os.ReadFile(plan.path)
	if e != nil {
		t.Fatal(e)
	}
	var got map[string]any
	json.Unmarshal(b, &got)
	if got["ownerEvidence"] != "preserved" || got["configReconciled"] != true || got["phase"] != "complete" || got["complete"] != true {
		t.Fatalf("bad acknowledgement: %s", b)
	}
}
func TestConfigRecoveryReloadFailureRetainsPendingAndRetries(t *testing.T) {
	s, record, current, reloads, _ := recoveryFixture(t)
	normal := s.writeConfig
	s.writeConfig = func(ctx context.Context, before, desired string, r *systemops.Reporter) error {
		normal(ctx, before, desired, r)
		return errors.New("reload failed")
	}
	plan, e := s.prepare(context.Background(), record.Target)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.execute(context.Background(), plan, nil); e == nil {
		t.Fatal("reload failure hidden")
	}
	pending, e := s.read(s.roots[0], record.Target)
	if e != nil || pending.record.ConfigReconciled {
		t.Fatal("failed reload acknowledged", e)
	}
	s.writeConfig = normal
	plan, e = s.prepare(context.Background(), record.Target)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.execute(context.Background(), plan, nil); e != nil {
		t.Fatal(e)
	}
	if *current != record.FstabDesired || *reloads != 2 {
		t.Fatal("already desired retry must reload")
	}
}
func TestConfigRecoveryBeforePreservesLiveUUIDAndUncertainStep(t *testing.T) {
	s, record, current, _, save := recoveryFixture(t)
	record.ConfigOnlyRemaining = false
	record.Steps[0].Completed = false
	save()
	p, _ := s.preflight(context.Background())
	p.Inventory.Rows[record.Target]["uuid"] = "old"
	plan, e := s.prepare(context.Background(), record.Target)
	if e != nil {
		t.Fatal(e)
	}
	if plan.resolution != "before" {
		t.Fatal("live UUID row must be preserved")
	}
	if _, e = s.execute(context.Background(), plan, nil); e != nil {
		t.Fatal(e)
	}
	pending, e := s.read(s.roots[0], record.Target)
	if e != nil {
		t.Fatal(e)
	}
	if pending.record.Phase != "pending" || pending.record.Steps[0].Completed || !pending.record.Acknowledged(*current, record.FstabBefore, record.FstabDesired) {
		t.Fatal("uncertain disk step falsely completed")
	}
}
func TestConfigRecoveryRejectsUnsafeEvidence(t *testing.T) {
	for _, scenario := range []string{"foreign-config", "live-after-completion", "changed-boot", "changed-hardware", "unknown-uuid", "arbitrary-desired", "foreign-journal"} {
		t.Run(scenario, func(t *testing.T) {
			s, record, current, _, save := recoveryFixture(t)
			switch scenario {
			case "foreign-config":
				*current += "# foreign\n"
			case "live-after-completion":
				p, _ := s.preflight(context.Background())
				p.Inventory.Rows[record.Target]["uuid"] = "old"
			case "changed-boot", "changed-hardware":
				base := s.identity
				s.identity = func(p *storagequery.Preflight, path string) (storagequery.StorageIdentity, error) {
					id, e := base(p, path)
					id.Devices = append([]storagequery.DeviceIdentity(nil), id.Devices...)
					if scenario == "changed-boot" {
						id.BootID = "boot-b"
					} else {
						id.Devices[0].DiskSequence = "99"
					}
					return id, e
				}
			case "unknown-uuid":
				record.ConfigRemovedUUIDs = []string{"foreign"}
				save()
			case "arbitrary-desired":
				record.FstabDesired = "UUID=foreign /other ext4 defaults 0 2\n"
				save()
			case "foreign-journal":
				normal := s.writeConfig
				s.writeConfig = func(ctx context.Context, before, desired string, r *systemops.Reporter) error {
					e := normal(ctx, before, desired, r)
					record.Action = "filesystem.remove"
					save()
					return e
				}
			}
			plan, e := s.prepare(context.Background(), record.Target)
			if scenario == "foreign-journal" {
				if e != nil {
					t.Fatal(e)
				}
				_, e = s.execute(context.Background(), plan, nil)
			}
			if e == nil {
				t.Fatal("unsafe state accepted")
			}
		})
	}
}
func TestConfigAcknowledgementRequiresExactCurrentWitness(t *testing.T) {
	c := ConfigRecovery{ConfigReconciled: true, ConfigResolution: "before", ConfigWitness: Hash("original")}
	if !c.Acknowledged("original", Hash("original"), "desired") || c.Acknowledged("foreign", Hash("original"), "desired") {
		t.Fatal("bad before CAS")
	}
	c.ConfigOnlyRemaining = true
	if c.Acknowledged("original", Hash("original"), "desired") {
		t.Fatal("completed disk writes cannot cancel config")
	}
}

func TestConfigRecoveryRetainsOwnerWorkAndUnknownSteps(t *testing.T) {
	for _, kind := range []string{"uncertain-device", "unknown-step", "stage", "mount"} {
		t.Run(kind, func(t *testing.T) {
			s, record, _, _, save := recoveryFixture(t)
			switch kind {
			case "uncertain-device":
				record.Steps[0].Completed = false
			case "unknown-step":
				record.Steps[0].Name = "unknown"
			case "stage":
				record.Stage = "/private/stage"
			case "mount":
				record.MountID = 55
			}
			save()
			plan, e := s.prepare(context.Background(), record.Target)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.execute(context.Background(), plan, nil); e != nil {
				t.Fatal(e)
			}
			pending, e := s.read(s.roots[0], record.Target)
			if e != nil || pending == nil || pending.record.Phase != "pending" || !pending.record.ConfigReconciled {
				t.Fatal("owner work incorrectly cleared", e)
			}
		})
	}
}
func TestConfigRecoveryAcknowledgementFailureCanRetryWithoutDiskReplay(t *testing.T) {
	s, record, _, reloads, _ := recoveryFixture(t)
	normal := s.write
	s.write = func(string, string, os.FileMode) error { return errors.New("full journal filesystem") }
	plan, e := s.prepare(context.Background(), record.Target)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.execute(context.Background(), plan, nil); e == nil {
		t.Fatal("lost acknowledgement ignored")
	}
	s.write = normal
	plan, e = s.prepare(context.Background(), record.Target)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.execute(context.Background(), plan, nil); e != nil {
		t.Fatal(e)
	}
	if *reloads != 2 {
		t.Fatal("retry skipped reload")
	}
}
func TestConfigRecoveryRejectsAddedAncestorAndEpochMismatch(t *testing.T) {
	for _, kind := range []string{"ancestor", "saved-epoch"} {
		t.Run(kind, func(t *testing.T) {
			s, record, _, _, save := recoveryFixture(t)
			if kind == "saved-epoch" {
				record.ConfigIdentity.BootID = "other-boot"
				save()
			} else {
				base := s.identity
				s.identity = func(p *storagequery.Preflight, path string) (storagequery.StorageIdentity, error) {
					id, e := base(p, path)
					id.Devices = append(append([]storagequery.DeviceIdentity(nil), id.Devices...), storagequery.DeviceIdentity{Path: "/dev/foreign", DeviceNumber: "8:0", DiskSequence: "99"})
					return id, e
				}
			}
			if _, e := s.prepare(context.Background(), record.Target); e == nil {
				t.Fatal("identity drift accepted")
			}
		})
	}
}
