package disksleep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestIdleClock(t *testing.T) {
	d := disk{Path: "/dev/sda"}
	base := advance(state{}, d, 10, 100, sample{}, false)
	if base.IdleSince != 100 {
		t.Fatal(base)
	}
	for n := 130.; n <= 700; n += 30 {
		base = advance(base, d, 10, n, sample{}, false)
	}
	if base.IdleSince != 100 {
		t.Fatal("idle clock reset", base)
	}
	tests := []struct {
		name    string
		prev    state
		now     float64
		minutes int
		sample  sample
		busy    bool
	}{
		{"read", base, 730, 10, sample{Counters: [7]uint64{1}}, false},
		{"flush", base, 730, 10, sample{Counters: [7]uint64{0, 0, 0, 0, 0, 0, 1}}, false},
		{"inflight", base, 730, 10, sample{InFlight: 1}, false},
		{"raid", base, 730, 10, sample{}, true},
		{"configuration", base, 730, 5, sample{}, false},
		{"monitor stopped", base, 850, 10, sample{}, false},
		{"clock reset", base, 5, 10, sample{}, false},
		{"hotplug", state{}, 730, 10, sample{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := advance(tt.prev, d, tt.minutes, tt.now, tt.sample, tt.busy)
			if got.IdleSince != tt.now {
				t.Fatal(got)
			}
		})
	}
}
func TestStats(t *testing.T) {
	s, e := parseStats("1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17")
	if e != nil || s.Counters != [7]uint64{1, 3, 5, 7, 12, 14, 16} || s.InFlight != 9 {
		t.Fatal(s, e)
	}
	for _, text := range []string{"", "1 2", "a 0 0 0 0 0 0 0 0 0 0"} {
		if _, e := parseStats(text); e == nil {
			t.Fatal(text)
		}
	}
}
func TestProtection(t *testing.T) {
	root := device{Kind: "disk", Children: []device{{Kind: "raid6", Children: []device{{Kind: "crypt", Mounts: []string{"/"}}}}}}
	if !protected(root, nil) {
		t.Fatal("OS on encrypted RAID not protected")
	}
	root.Children[0].Children[0].Mounts = []string{"/srv/data"}
	if protected(root, nil) {
		t.Fatal("data RAID protected")
	}
	root.Children[0].Children[0].UUID = "system"
	if !protected(root, map[string]bool{"UUID=system": true}) {
		t.Fatal("fstab system filesystem missed")
	}
	for _, d := range []device{{ReadOnly: true}, {FSType: "swap"}, {PartType: "0xef"}, {Mounts: []string{"/boot/firmware"}}} {
		if !protected(d, nil) {
			t.Fatal(d)
		}
	}
}
func fixture(t *testing.T) (*service, disk, *[]string) {
	t.Helper()
	dir := t.TempDir()
	s := &service{sys: filepath.Join(dir, "sys"), fstab: filepath.Join(dir, "fstab")}
	d := disk{"/dev/sda", "sda", "serial:7"}
	for _, path := range []string{"sda/holders", "sda/md"} {
		if e := os.MkdirAll(filepath.Join(s.sys, path), 0755); e != nil {
			t.Fatal(e)
		}
	}
	for path, value := range map[string]string{"sda/diskseq": "7", "sda/stat": "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0", "sda/md/sync_action": "idle"} {
		if e := os.WriteFile(filepath.Join(s.sys, path), []byte(value), 0600); e != nil {
			t.Fatal(e)
		}
	}
	os.WriteFile(s.fstab, nil, 0600)
	calls := []string{}
	s.run = func(name string, args ...string) ([]byte, int, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch name {
		case "lsblk":
			return []byte(`{"blockdevices":[{"kname":"sda","path":"/dev/sda","type":"disk","tran":"sata","serial":"serial","rota":true}]}`), 0, nil
		case "smartctl":
			return []byte(`{"ata_smart_data":{"self_test":{"status":{"value":0}}}}`), 0, nil
		}
		return nil, 0, nil
	}
	return s, d, &calls
}
func TestStandbyGates(t *testing.T) {
	for _, kind := range []string{"idle", "sleeping", "self-test", "offline-test", "unknown-smart", "raid", "changed-id", "io-during-smart", "firmware-failure", "disabled"} {
		t.Run(kind, func(t *testing.T) {
			s, d, calls := fixture(t)
			real := s.run
			s.run = func(name string, args ...string) ([]byte, int, error) {
				if name == "smartctl" {
					switch kind {
					case "sleeping":
						return []byte(`{"smartctl":{"messages":[{"string":"Device is in STANDBY mode"}]}}`), 3, fmt.Errorf("exit 3")
					case "self-test":
						return []byte(`{"ata_smart_data":{"self_test":{"status":{"value":249}}}}`), 0, nil
					case "offline-test":
						return []byte(`{"ata_smart_data":{"self_test":{"status":{"value":0}},"offline_data_collection":{"status":{"value":3}}}}`), 0, nil
					case "unknown-smart":
						return []byte(`{}`), 0, nil
					case "changed-id":
						os.WriteFile(filepath.Join(s.sys, "sda/diskseq"), []byte("8"), 0600)
					case "io-during-smart":
						os.WriteFile(filepath.Join(s.sys, "sda/stat"), []byte("1 0 8 0 0 0 0 0 0 0 0"), 0600)
					}
				}
				if kind == "firmware-failure" && name == "hdparm" {
					return nil, 1, fmt.Errorf("failed")
				}
				return real(name, args...)
			}
			if kind == "raid" || kind == "disabled" {
				os.WriteFile(filepath.Join(s.sys, "sda/md/sync_action"), []byte("resync"), 0600)
			}
			old := state{Version: 1, Minutes: 10, Seen: 690, IdleSince: 100, Status: "applied"}
			minutes := 10
			if kind == "disabled" {
				minutes = 0
			}
			if kind == "firmware-failure" {
				old.Version = 0
			}
			result, err := s.step(d, old, minutes, 710)
			sent := false
			for _, c := range *calls {
				if c == "hdparm -y /dev/sda" {
					sent = true
				}
			}
			if sent != (kind == "idle") {
				t.Fatalf("standby=%v calls=%v result=%+v err=%v", sent, *calls, result, err)
			}
			if kind == "disabled" && result.Status != "applied" {
				t.Fatal(result)
			}
			if kind == "unknown-smart" && err == nil {
				t.Fatal("unknown SMART accepted")
			}
			if kind == "sleeping" && !result.Sleeping {
				t.Fatal(result)
			}
			if kind == "idle" {
				*calls = nil
				result.Seen = 710
				result, err = s.step(d, result, 10, 740)
				for _, c := range *calls {
					if c == "hdparm -y /dev/sda" {
						t.Fatal("repeated standby", result, err)
					}
				}
			}
		})
	}
}
func TestBusyPartitionGraph(t *testing.T) {
	s, _, _ := fixture(t)
	for _, path := range []string{"sda/sda1", "sda1/holders/md0", "md0/holders", "md0/md"} {
		os.MkdirAll(filepath.Join(s.sys, path), 0755)
	}
	os.WriteFile(filepath.Join(s.sys, "sda/sda1/partition"), []byte("1"), 0600)
	os.WriteFile(filepath.Join(s.sys, "md0/md/sync_action"), []byte("reshape"), 0600)
	b, e := s.busy("sda", map[string]bool{})
	if !b || e != nil {
		t.Fatal(b, e)
	}
}
func TestConfigValidation(t *testing.T) {
	for _, text := range []string{`{}`, `{"minutes":true}`, `{"minutes":"10"}`, `{"minutes":1}`, `{"minutes":10.5}`, `null`} {
		if _, err := decodeConfig([]byte(text)); err == nil {
			t.Fatal(text)
		}
	}
	for _, m := range []int{0, 5, 10, 15, 20, 30, 60, 120, 180, 300} {
		raw, _ := json.Marshal(config{m})
		v, err := decodeConfig(raw)
		if err != nil || !reflect.DeepEqual(v, &config{m}) {
			t.Fatal(v, err)
		}
	}
}

func TestApplyMigrationAndLock(t *testing.T) {
	s, d, calls := fixture(t)
	root := filepath.Dir(s.fstab)
	s.config = filepath.Join(root, "config")
	s.state = filepath.Join(root, "state")
	s.lock = filepath.Join(root, "lock")
	s.uptime = filepath.Join(root, "uptime")
	os.WriteFile(s.config, []byte(`{"minutes":10}`), 0600)
	os.WriteFile(s.uptime, []byte("1000 0"), 0600)
	os.WriteFile(s.state, []byte(`{"serial:7":{"minutes":10,"status":"applied"}}`), 0600)
	if err := s.apply(false); err != nil {
		t.Fatal(err)
	}
	states, err := s.readState()
	if err != nil {
		t.Fatal(err)
	}
	if states[d.Key].Version != 1 || states[d.Key].IdleSince != 1000 {
		t.Fatal(states)
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "hdparm -S 0 /dev/sda") {
		t.Fatal("legacy firmware timeout not disabled")
	}
	*calls = nil
	if err := s.locked(false, func() error { return s.apply(false) }); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatal("controller ran while storage operation held the lock", *calls)
	}
	os.WriteFile(s.state, []byte(`broken`), 0600)
	if err := s.apply(false); err != nil {
		t.Fatal(err)
	}
	states, err = s.readState()
	if err != nil || states[d.Key].IdleSince != 1000 {
		t.Fatal(states, err)
	}
}

func TestRuntimeRequiresFreshObservation(t *testing.T) {
	s, d, _ := fixture(t)
	root := filepath.Dir(s.fstab)
	s.config = filepath.Join(root, "config")
	s.state = filepath.Join(root, "state")
	s.uptime = filepath.Join(root, "uptime")
	os.WriteFile(s.config, []byte(`{"minutes":10}`), 0600)
	os.WriteFile(s.uptime, []byte("1000 0"), 0600)
	st := state{Version: 1, Minutes: 10, Status: "applied", Seen: 995}
	s.writeState(map[string]state{d.Key: st})
	real := s.run
	props := "ActiveState=active\nUnitFileState=enabled\n"
	s.run = func(name string, args ...string) ([]byte, int, error) {
		if name == "systemctl" {
			return []byte(props), 0, nil
		}
		return real(name, args...)
	}
	check := func(want string) {
		t.Helper()
		v, e := s.query()
		if e != nil {
			t.Fatal(e)
		}
		got := v.(map[string]any)["sleepRuntime"].(map[string]any)["status"]
		if got != want {
			t.Fatalf("%v != %s", got, want)
		}
	}
	check("applied")
	props = "ActiveState=inactive\nUnitFileState=disabled\n"
	check("inactive")
	props = "ActiveState=active\nUnitFileState=enabled\n"
	st.Seen = 800
	s.writeState(map[string]state{d.Key: st})
	check("pending")
	st.Status = "error"
	s.writeState(map[string]state{d.Key: st})
	check("error")
	st.Status = "busy"
	s.writeState(map[string]state{d.Key: st})
	check("busy")
	st.Status = "applied"
	st.Seen = 995
	st.Minutes = 0
	s.writeState(map[string]state{d.Key: st})
	os.WriteFile(s.config, []byte(`{"minutes":0}`), 0600)
	check("disabled")
}
