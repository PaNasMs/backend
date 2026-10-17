package oled

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFreshInstallAndPinValidation(t *testing.T) {
	s, err := readConfig(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || s.Enabled || s.SDA != 2 || s.SCL != 3 || s.Bus != 1 {
		t.Fatalf("fresh config: %+v %v", s, err)
	}
	for _, mutate := range []func(*Settings){
		func(s *Settings) { s.SDA = 0; s.SCL = 1; s.Bus = 0 },
		func(s *Settings) { s.SCL = 5 },
		func(s *Settings) { s.Bus = 13 },
		func(s *Settings) { s.Brightness = 0 },
		func(s *Settings) { s.Brightness = 101 },
		func(s *Settings) { s.Rotation = 90 },
		func(s *Settings) { s.Address = 0x50 },
		func(s *Settings) { s.Controller = "unknown" },
		func(s *Settings) { s.Enabled = true; s.ShowIP = false; s.ShowCPU = false; s.ShowDisks = false },
	} {
		next := s
		mutate(&next)
		if next.Validate() == nil {
			t.Fatalf("accepted invalid config: %+v", next)
		}
	}
	for sda, bus := range map[int]int{2: 1, 10: 1, 4: 2, 12: 2, 6: 3, 14: 3, 22: 3, 8: 0} {
		next := s
		next.SDA = sda
		next.SCL = sda + 1
		next.Bus = bus
		if err := next.Validate(); err != nil {
			t.Fatalf("valid pair rejected: %+v: %v", next, err)
		}
	}
}
func TestObservedStateRequiresFreshMatchingConfiguration(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	status := filepath.Join(dir, "status.json")
	now := time.Now()
	cfg := Defaults()
	cfg.Enabled = true
	if err := atomicJSON(config, cfg); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		age      time.Duration
		mismatch bool
		failure  string
		want     string
	}{
		{"active", 0, false, "", "active"}, {"stale", 11 * time.Second, false, "", "unavailable"},
		{"future", -time.Minute, false, "", "unavailable"}, {"old settings", 0, true, "", "starting"},
		{"hardware error", 0, false, "write failed", "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applied := cfg
			if tc.mismatch {
				applied.Brightness++
			}
			if err := atomicJSON(status, Status{ObservedAt: now.Add(-tc.age), Applied: applied, Error: tc.failure}); err != nil {
				t.Fatal(err)
			}
			got, err := readState(config, status, true, now)
			if err != nil || got.State != tc.want {
				t.Fatalf("%+v %v", got, err)
			}
		})
	}
	cfg.Enabled = false
	_ = atomicJSON(config, cfg)
	got, err := readState(config, status, true, now)
	if err != nil || got.State != "disabled" {
		t.Fatalf("%+v %v", got, err)
	}
	if err := os.WriteFile(config, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(config, status, true, now); err == nil {
		t.Fatal("invalid config silently accepted")
	}
}
func TestReadingsAndIPv6FitDisplay(t *testing.T) {
	cfg := Defaults()
	cpu := 43.5
	got := lines(cfg, "panasms", "192.168.1.100", &cpu, map[string]float64{"a": 30, "b": 37})
	want := []string{"panasms", "IP 192.168.1.100", "CPU 43.5 C", "HDD MAX 37.0 C"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
	for _, ip := range []string{"2001:db8:1234::1234", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		got = lines(cfg, "nas", ip, nil, nil)
		if len(got) > 5 || strings.Join(got[1:len(got)-2], "") != ip {
			t.Fatalf("IPv6 truncated: %q", got)
		}
		for _, line := range got {
			if len(line) > 20 {
				t.Fatalf("line overflow: %q", line)
			}
		}
	}
	cfg.ShowIP = false
	cfg.ShowDisks = false
	if got = lines(cfg, "nas", "", nil, nil); !reflect.DeepEqual(got, []string{"nas", "CPU --"}) {
		t.Fatalf("%q", got)
	}
}
func TestRotationAndFrameBounds(t *testing.T) {
	text := []string{strings.Repeat("W", 40), "IP 192.168.100.100", "CPU 43.5 C", "HDD MAX 37.0 C", "last row", "ignored"}
	for shift := 0; shift <= 1; shift++ {
		normal := Render(text, 0, shift)
		rotated := Render(text, 180, shift)
		count := 0
		for y := 0; y < 64; y++ {
			for x := 0; x < 128; x++ {
				bit := normal[y/8*128+x]&(1<<uint(y%8)) != 0
				mirrored := rotated[(63-y)/8*128+127-x]&(1<<uint((63-y)%8)) != 0
				if bit != mirrored {
					t.Fatalf("rotation mismatch %d,%d", x, y)
				}
				if bit {
					count++
					if x < 2 || x > 122 || y < 2 || y > 57 {
						t.Fatalf("pixel escaped safe area %d,%d", x, y)
					}
				}
			}
		}
		if count == 0 {
			t.Fatal("empty frame")
		}
	}
	if !reflect.DeepEqual(pageCommand("ssd1306", 7), []byte{0xb7, 0, 0x10}) || !reflect.DeepEqual(pageCommand("sh1106", 0), []byte{0xb0, 2, 0x10}) {
		t.Fatal("incorrect page addressing")
	}
}
