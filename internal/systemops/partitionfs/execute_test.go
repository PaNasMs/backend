package partitionfs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"panasms.local/backend/internal/systemops/storagebase"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagequery"
)

func executionFixture(t *testing.T) (*service, *prepared) {
	s, p := planningFixture(t)
	s.revalidate = func(context.Context, string, *transaction) error { return nil }
	s.write = func(path, data string, mode os.FileMode) error { return os.WriteFile(path, []byte(data), mode) }
	s.writeConfig = func(context.Context, string, string, *systemops.Reporter) error {
		t.Fatal("unexpected configuration mutation")
		return nil
	}
	identity, _ := s.identity(p, "/dev/sda1")
	row := p.Inventory.Rows["/dev/sda1"]
	row["size"] = json.Number("67108864")
	row["fstype"] = "ext4"
	table := map[string]any{"label": "gpt", "sectorsize": json.Number("512"), "partitions": []any{map[string]any{"node": "/dev/sda1", "start": json.Number("2048"), "size": json.Number("131072")}}}
	plan := &prepared{target: "/dev/sda1", parent: "/dev/sda", row: row, table: table, identity: identity, fingerprint: strings.Repeat("a", 64), config: "# retained\n", start: 1048576, size: 32}
	return s, plan
}
func TestResizeOrderingAndUncertainStepRetained(t *testing.T) {
	for _, shrinking := range []bool{true, false} {
		t.Run(map[bool]string{true: "shrink", false: "grow"}[shrinking], func(t *testing.T) {
			s, p := executionFixture(t)
			if !shrinking {
				p.size = 128
			}
			calls := []string{}
			s.run = func(_ context.Context, args []string, opts systemops.CommandOptions) ([]byte, error) {
				if len(args) > 1 && args[0] == "sfdisk" && args[1] == "--json" {
					return updatedTable(p), nil
				}
				calls = append(calls, args[0]+" "+strings.Join(args[1:], " "))
				if args[0] == "partx" {
					if err := os.WriteFile(filepath.Join(s.sys, "sda1/size"), []byte(json.Number(stringify(p.size*2048))), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return nil, nil
			}
			_, err := s.executePrepared(context.Background(), "partition.resize", nil, p, nil)
			if err != nil {
				t.Fatal(err)
			}
			sequence := []string{}
			for _, call := range calls {
				sequence = append(sequence, strings.Fields(call)[0])
			}
			want := []string{"e2fsck", "sfdisk", "partx", "udevadm", "resize2fs"}
			if shrinking {
				want = []string{"e2fsck", "resize2fs", "sfdisk", "partx", "udevadm", "resize2fs"}
			}
			if !reflect.DeepEqual(sequence, want) {
				t.Fatalf("%v != %v", sequence, want)
			}
			state, err := s.load(p.target)
			if err != nil || !state.Complete {
				t.Fatalf("%v %v", state, err)
			}
		})
	}
	s, p := executionFixture(t)
	calls := []string{}
	s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
		if len(args) > 1 && args[0] == "sfdisk" && args[1] == "--json" {
			return updatedTable(p), nil
		}
		calls = append(calls, args[0])
		if args[0] == "sfdisk" {
			return nil, errors.New("injected uncertain write")
		}
		return nil, nil
	}
	if _, err := s.executePrepared(context.Background(), "partition.resize", nil, p, nil); err == nil {
		t.Fatal("injected failure ignored")
	}
	if !reflect.DeepEqual(calls, []string{"e2fsck", "resize2fs", "sfdisk"}) {
		t.Fatal(calls)
	}
	state, err := s.load(p.target)
	if err != nil || state.Complete || state.Steps[len(state.Steps)-1].Completed {
		t.Fatalf("%+v %v", state, err)
	}
	if state.Steps[len(state.Steps)-1].Name != "resize-partition" {
		t.Fatal(state)
	}
}
func stringify(n uint64) string { data, _ := json.Marshal(n); return string(data) }
func TestKernelMismatchDoesNotGrowFilesystem(t *testing.T) {
	s, p := executionFixture(t)
	calls := []string{}
	s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
		if len(args) > 1 && args[0] == "sfdisk" && args[1] == "--json" {
			return updatedTable(p), nil
		}
		calls = append(calls, args[0])
		return nil, nil
	}
	if _, err := s.executePrepared(context.Background(), "partition.resize", nil, p, nil); err == nil || !strings.Contains(err.Error(), "kernel has not confirmed") {
		t.Fatalf("%v", err)
	}
	if !reflect.DeepEqual(calls, []string{"e2fsck", "resize2fs", "sfdisk", "partx", "udevadm"}) {
		t.Fatal(calls)
	}
	state, err := s.load(p.target)
	if err != nil || state.Complete {
		t.Fatalf("%v %v", state, err)
	}
}
func TestCancellationAfterShrinkNeverRepeatsOrStartsPartitionWrite(t *testing.T) {
	s, p := executionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := []string{}
	s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
		if len(args) > 1 && args[0] == "sfdisk" && args[1] == "--json" {
			return updatedTable(p), nil
		}
		calls = append(calls, args[0])
		if args[0] == "resize2fs" {
			cancel()
		}
		return nil, nil
	}
	if _, err := s.executePrepared(ctx, "partition.resize", nil, p, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"e2fsck", "resize2fs"}) {
		t.Fatal(calls)
	}
	state, err := s.load(p.target)
	if err != nil || state.Complete || len(state.Steps) != 2 || !state.Steps[1].Completed {
		t.Fatalf("%v %v", state, err)
	}
}
func TestFilesystemUUIDMayChangeButHardwareIdentityMustNot(t *testing.T) {
	a := storagequery.StorageIdentity{BootID: "a", Devices: []storagequery.DeviceIdentity{{Path: "/dev/sda1", DeviceNumber: "8:1", DiskSequence: "3", UUID: "old"}}}
	b := a
	b.Devices = append([]storagequery.DeviceIdentity{}, a.Devices...)
	b.Devices[0].UUID = "new"
	if !hardwareEqual(a, b) {
		t.Fatal("expected filesystem metadata transition refused")
	}
	b.Devices[0].DiskSequence = "4"
	if hardwareEqual(a, b) {
		t.Fatal("replacement hardware accepted")
	}
}

func TestReplacementBeforeNextWriteRetainsIntentAndStops(t *testing.T) {
	s, p := executionFixture(t)
	calls := []string{}
	checks := 0
	s.revalidate = func(context.Context, string, *transaction) error {
		checks++
		if checks == 2 {
			return errors.New("device incarnation changed")
		}
		return nil
	}
	s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
		if len(args) > 1 && args[0] == "sfdisk" && args[1] == "--json" {
			return updatedTable(p), nil
		}
		calls = append(calls, args[0])
		return nil, nil
	}
	if _, err := s.executePrepared(context.Background(), "partition.resize", nil, p, nil); err == nil {
		t.Fatal("replacement accepted")
	}
	if !reflect.DeepEqual(calls, []string{"e2fsck"}) {
		t.Fatal(calls)
	}
	state, err := s.load(p.target)
	if err != nil || state.Complete || state.Phase != "pending" || len(state.Steps) != 1 {
		t.Fatalf("%v %v", state, err)
	}
}

func updatedTable(p *prepared) []byte {
	table := map[string]any{"label": "gpt", "sectorsize": json.Number("512"), "partitions": []any{map[string]any{"node": p.target, "start": json.Number("2048"), "size": json.Number(stringify(p.size * 2048))}}}
	data, _ := json.Marshal(map[string]any{"partitiontable": table})
	return data
}

func TestFailedSuccessorJournalDoesNotHideUnresolvedEvidence(t *testing.T) {
	s, p := executionFixture(t)
	old := &transaction{Schema: 1, Domain: "partitionfs", Phase: "pending", Action: "partition.resize", Target: p.target, Fingerprint: p.fingerprint, Identity: p.identity, Steps: []step{{Name: "resize-partition"}}, FstabBefore: storagebase.Hash(p.config), FstabDesired: p.config}
	if err := s.save(old); err != nil {
		t.Fatal(err)
	}
	p.previous = old
	s.write = func(string, string, os.FileMode) error { return errors.New("injected full filesystem") }
	s.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
		t.Fatal("ran command without durable intent")
		return nil, nil
	}
	if _, err := s.executePrepared(context.Background(), "partition.resize", nil, p, nil); err == nil {
		t.Fatal("persist failure ignored")
	}
	after, err := s.load(p.target)
	if err != nil || !reflect.DeepEqual(after, old) {
		t.Fatalf("lost active unresolved journal: %+v %v", after, err)
	}
	files, err := filepath.Glob(filepath.Join(s.root, "*.history-*"))
	if err != nil || len(files) != 1 {
		t.Fatalf("%v %v", files, err)
	}
}

func TestFormatConfigFailureRetainsIdentityAndRequiresRecovery(t *testing.T) {
	for _, afterWrite := range []bool{false, true} {
		t.Run(fmt.Sprint(afterWrite), func(t *testing.T) {
			s, p := executionFixture(t)
			p.config = "UUID=old /data ext4 defaults 0 2\n"
			p.row["uuid"] = "old"
			p.identity.Devices[0].UUID = "old"
			s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
				if args[0] == "mkfs.ext4" {
					p.row["uuid"] = "new"
				}
				return nil, nil
			}
			config := p.config
			s.writeConfig = func(_ context.Context, _ string, desired string, _ *systemops.Reporter) error {
				if afterWrite {
					config = desired
				}
				return errors.New("injected configuration failure")
			}
			if _, err := s.executePrepared(context.Background(), "filesystem.format", map[string]any{"format": "ext4"}, p, nil); err == nil {
				t.Fatal("failure hidden")
			}
			state, err := s.load(p.target)
			if err != nil {
				t.Fatal(err)
			}
			if !state.ConfigOnlyRemaining || state.ConfigIdentity.BootID != state.Identity.BootID || state.ConfigReconciled || state.Complete || !reflect.DeepEqual(state.ConfigRemovedUUIDs, []string{"old"}) {
				t.Fatalf("missing durable recovery proof: %+v", state)
			}
			p.previous = state
			p.config = config
			s.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
				t.Fatal("destructive replay before config acknowledgement")
				return nil, nil
			}
			if _, err = s.executePrepared(context.Background(), "filesystem.format", map[string]any{"format": "ext4"}, p, nil); err == nil {
				t.Fatal("unacknowledged intent superseded")
			}
		})
	}
}

func TestPartitionCreateKernelFailureRemainsPending(t *testing.T) {
	for _, failure := range []string{"command", "mismatch"} {
		t.Run(failure, func(t *testing.T) {
			s, p := executionFixture(t)
			p.target = "/dev/sda"
			p.start, p.end = 128, 160
			s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
				if len(args) > 1 && args[0] == "sfdisk" && args[1] == "--json" {
					return []byte(`{"partitiontable":{"label":"gpt","sectorsize":512,"partitions":[{"node":"/dev/sda1","start":2048,"size":131072},{"node":"/dev/sda2","start":262144,"size":65536}]}}`), nil
				}
				if args[0] == "partx" && failure == "command" {
					return nil, errors.New("injected kernel sync failure")
				}
				return nil, nil
			}
			if _, err := s.executePrepared(context.Background(), "partition.create", nil, p, nil); err == nil {
				t.Fatal("kernel sync failure reported success")
			}
			state, err := s.load(p.target)
			if err != nil || state == nil || state.Complete || state.Phase != "pending" {
				t.Fatalf("%+v %v", state, err)
			}
		})
	}
}
