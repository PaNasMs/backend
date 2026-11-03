package partitionfs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
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
	table := map[string]any{"label": "gpt", "sectorsize": json.Number("512")}
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
