package storagequery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRaidCandidatesUseMembersProtectRootAndRejectBusy(t *testing.T) {
	root := t.TempDir()
	data := `[
 {"path":"/dev/sda","kname":"sda","type":"disk","ro":false,"mountpoints":[],"size":100,"children":[{"path":"/dev/sda1","kname":"sda1","type":"part","ro":false,"size":90,"mountpoints":["/"]}]},
 {"path":"/dev/md0","kname":"md0","type":"raid1","ro":false,"mountpoints":[],"size":80},
 {"path":"/dev/sdb","kname":"sdb","type":"disk","ro":false,"mountpoints":[],"size":80,"fstype":"linux_raid_member"},
 {"path":"/dev/sdc","kname":"sdc","type":"disk","ro":false,"mountpoints":[],"size":90,"fstype":null},
 {"path":"/dev/sdd","kname":"sdd","type":"disk","ro":false,"mountpoints":[],"size":70},
 {"path":"/dev/sde","kname":"sde","type":"disk","ro":false,"mountpoints":[],"size":100},
 {"path":"/dev/sdf","kname":"sdf","type":"disk","ro":false,"mountpoints":[],"size":100,"ro":true}]`
	var rows []map[string]any
	if err := json.Unmarshal([]byte(data), &rows); err != nil {
		t.Fatal(err)
	}
	sys := filepath.Join(root, "sys")
	for _, name := range []string{"sda", "sda1", "sdb", "sdc", "sdd", "sde", "sdf", "md0"} {
		for _, dir := range []string{"slaves", "holders"} {
			if err := os.MkdirAll(filepath.Join(sys, name, dir), 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, path := range []string{"md0/md", "md0/slaves/sdb", "sde/holders/dm-1"} {
		if err := os.MkdirAll(filepath.Join(sys, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	fstab := filepath.Join(root, "fstab")
	if err := os.WriteFile(fstab, nil, 0600); err != nil {
		t.Fatal(err)
	}
	s := &service{sys, fstab, func(context.Context) ([]map[string]any, error) { return rows, nil }, func(path string) (string, error) {
		if path == "/dev/md/alias" {
			return "/dev/md0", nil
		}
		return path, nil
	}}
	result, err := s.raidCandidates(context.Background(), "/dev/md/alias")
	if err != nil {
		t.Fatal(err)
	}
	candidates := result.(map[string]any)["devices"].([]map[string]any)
	if len(candidates) != 1 || candidates[0]["path"] != "/dev/sdc" {
		t.Fatalf("%v", candidates)
	}
	inv, err := NewInventory(rows, s.resolve)
	if err != nil {
		t.Fatal(err)
	}
	expected := legacyQuery(t, root, inv, "raid-candidates", "/dev/md0", result)
	encoded, _ := json.Marshal(result)
	var normalized any
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, normalized) {
		t.Fatalf("Go %v Python %v", normalized, expected)
	}
	if err := os.Mkdir(filepath.Join(sys, "md0/slaves/gone"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.raidCandidates(context.Background(), "/dev/md0"); err == nil {
		t.Fatal("missing member allowed")
	}
}

func TestPartialInventoryCannotBecomeSafeCandidate(t *testing.T) {
	good := map[string]any{"type": "disk", "size": float64(100), "ro": false, "mountpoints": []any{nil}}
	if err := validateObservation(good); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"type", "size", "ro", "mountpoints"} {
		row := map[string]any{}
		for k, v := range good {
			if k != key {
				row[k] = v
			}
		}
		if err := validateObservation(row); err == nil {
			t.Fatalf("missing %s accepted", key)
		}
	}
	for key, value := range map[string]any{"type": nil, "size": "100", "ro": "0", "mountpoints": []any{true}} {
		row := map[string]any{}
		for k, v := range good {
			row[k] = v
		}
		row[key] = value
		if err := validateObservation(row); err == nil {
			t.Fatalf("invalid %s accepted", key)
		}
	}
}
