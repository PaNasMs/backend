package raid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveOnlyMatchingMDConfig(t *testing.T) {
	uuid := "08b18fee-4bd0-0854-2c14-f992d6945192"
	original := "# ARRAY UUID=08b18fee:4bd00854:2c14f992:d6945192\nARRAY /dev/md/other metadata=1.2 UUID=different\n"
	if got := withoutArray(original+"ARRAY /dev/md/test metadata=1.2 UUID=08B18FEE:4BD00854:2C14F992:D6945192\n", uuid); got != original {
		t.Fatal(got)
	}
}
func TestDegradedResumeRequiresHealthySourceSlots(t *testing.T) {
	a := &arrayState{UUID: "array", Degraded: 1, Members: []member{{"/dev/a", "0", []string{"in_sync"}}, {"/dev/b", "1", []string{"in_sync"}}, {"/dev/c", "none", nil}}}
	r := &reshapeRecord{UUID: "array", Members: 3, SourceCount: 2}
	if !safeResume(a, r) {
		t.Fatal("complete source mirror with pending parity member")
	}
	for _, bad := range []string{"faulty", "blocked", "write_error"} {
		a.Members[2].State = []string{bad}
		if safeResume(a, r) {
			t.Fatal(bad)
		}
	}
	a.Members[2].State = nil
	a.Members[1].Slot = "0"
	if safeResume(a, r) {
		t.Fatal("duplicate source slot")
	}
	a.Members[1].Slot = "none"
	if safeResume(a, r) {
		t.Fatal("missing source slot")
	}
}
func TestLegacyReshapeRecord(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	s := service{reshapeRoot: root, owner: os.Getuid()}
	uuid := "08b18fee-4bd0-0854-2c14-f992d6945192"
	old := map[string]any{"uuid": uuid, "target": "/dev/md127", "level": "5", "members": 3, "backup": s.backup(uuid)}
	b, _ := json.Marshal(old)
	path := recordPath(s.backup(uuid))
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := s.record(uuid)
	if err != nil || got.SourceCount != 0 || got.Members != 3 {
		t.Fatalf("%+v %v", got, err)
	}
	if got, err := s.record("08b18fee:4bd00854:2c14f992:d6945192"); err != nil || got == nil {
		t.Fatalf("legacy UUID spelling: %v", err)
	}
	old["backup"] = "/tmp/outside"
	b, _ = json.Marshal(old)
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.record(uuid); err == nil {
		t.Fatal("accepted redirected recovery backup")
	}
}
func TestRAID0KernelState(t *testing.T) {
	root := t.TempDir()
	md := filepath.Join(root, "md127", "md")
	for _, m := range []string{"dev-loop0", "dev-loop1"} {
		if err := os.MkdirAll(filepath.Join(md, m), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []string{"loop0", "loop1"} {
		target := filepath.Join(root, m)
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(md, "dev-"+m, "block")); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{"uuid": "08b18fee-4bd0-0854-2c14-f992d6945192", "level": "raid0", "metadata_version": "1.2", "raid_disks": "2", "reshape_position": "none", "array_state": "clean", "component_size": "0", "chunk_size": "524288", "layout": "1", "dev-loop0/state": "in_sync", "dev-loop1/state": "in_sync", "dev-loop0/slot": "0", "dev-loop1/slot": "1"}
	for path, value := range files {
		if err := os.WriteFile(filepath.Join(md, path), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s := service{sys: root}
	a, err := s.readArray("md127")
	if err != nil || !synchronized(a) || a.Sync != "idle" {
		t.Fatalf("%v %v", a, err)
	}
	for name, value := range map[string]string{"raid_disks": "3 (2)", "chunk_size": "65536 (524288)", "reshape_position": "2048"} {
		if err = os.WriteFile(filepath.Join(md, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	a, err = s.readArray("md127")
	if err != nil || a.Count != 3 || a.Chunk != 65536 || !a.Reshaping {
		t.Fatalf("reshape geometry: %+v %v", a, err)
	}
	for _, k := range []string{"uuid", "raid_disks"} {
		p := filepath.Join(md, k)
		if err = os.WriteFile(p, []byte("bad"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = s.readArray("md127"); err == nil {
			t.Fatal("accepted " + k)
		}
		os.WriteFile(p, []byte(files[k]), 0600)
	}
}

func TestLegacyResumeWithoutRecord(t *testing.T) {
	a := &arrayState{Sync: "idle", Array: "active"}
	if safeResume(a, nil) {
		t.Fatal("idle reshape needs its journal")
	}
	a.Sync = "frozen"
	if !safeResume(a, nil) {
		t.Fatal("legacy running reshape can be unfrozen")
	}
	a.Array = "readonly"
	if safeResume(a, nil) {
		t.Fatal("cannot reactivate an unrecorded reshape")
	}
}
