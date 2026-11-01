package oled

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLayoutMigrationAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oled.json")
	if err := os.WriteFile(path, []byte(`{"enabled":true,"brightness":40,"sda":12,"scl":13,"bus":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := readConfig(path)
	if err != nil || cfg.Layout != "large" || cfg.PageSeconds != 6 || !cfg.Enabled || cfg.Brightness != 40 || cfg.SDA != 12 {
		t.Fatalf("migration: %+v %v", cfg, err)
	}
	for _, mutate := range []func(*Settings){func(s *Settings) { s.Layout = "unknown" }, func(s *Settings) { s.PageSeconds = 3 }, func(s *Settings) { s.PageSeconds = 61 }} {
		invalid := cfg
		mutate(&invalid)
		if invalid.Validate() == nil {
			t.Fatalf("accepted invalid layout config: %+v", invalid)
		}
	}
}
func TestLayoutsFitAndPreserveIPv6(t *testing.T) {
	cpu, disk := 103.5, 50.0
	ip := "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	data := Snapshot{Host: strings.Repeat("N", 50), IP: ip, CPU: &cpu, Disks: []Disk{{"nvme0n1", &disk}, {"sda", nil}}, Uptime: "100D 10:00"}
	for _, layout := range []string{"compact", "large", "disks", "pages"} {
		t.Run(layout, func(t *testing.T) {
			cfg := Defaults()
			cfg.Layout = layout
			for page := 0; page < 8; page++ {
				scene := Compose(cfg, data, page)
				for i, text := range scene {
					width := (len([]rune(text.Value))*6 - 1) * text.Scale
					if text.X < 2 || text.X+width > 125 || text.Y < 2 || text.Y+7*text.Scale > 62 {
						t.Fatalf("text clipped: %+v", text)
					}
					if i > 0 {
						prev := scene[i-1]
						if prev.Y+7*prev.Scale > text.Y {
							t.Fatalf("overlap: %+v", scene)
						}
					}
				}
				frame := RenderScene(scene, 0, 1)
				rotated := RenderScene(scene, 180, 1)
				for y := 0; y < 64; y++ {
					for x := 0; x < 128; x++ {
						bit := frame[y/8*128+x]&(1<<uint(y%8)) != 0
						mirror := rotated[(63-y)/8*128+127-x]&(1<<uint((63-y)%8)) != 0
						if bit != mirror {
							t.Fatal("rotation mismatch")
						}
						if bit && (x < 2 || x > 125 || y < 2 || y > 61) {
							t.Fatal("pixel outside safe bounds")
						}
					}
				}
			}
			values := ""
			for _, text := range Compose(cfg, data, 0) {
				values += text.Value
			}
			if !strings.Contains(values, ip) {
				t.Fatalf("IPv6 lost: %s", values)
			}
		})
	}
}
func TestDiskPagesAndReadingSelection(t *testing.T) {
	data := Snapshot{Host: "nas", IP: "192.168.1.100", Disks: []Disk{{Label: "sda"}, {Label: "sdb"}, {Label: "sdc"}, {Label: "sdd"}, {Label: "sde"}, {Label: "sdf"}, {Label: "sdg"}}}
	for _, layout := range []string{"disks", "pages"} {
		cfg := Defaults()
		cfg.Layout = layout
		all := ""
		for page := 0; page < 10; page++ {
			for _, text := range Compose(cfg, data, page) {
				all += text.Value + "\n"
			}
		}
		for _, disk := range data.Disks {
			if !strings.Contains(all, disk.Label) {
				t.Fatalf("%s omitted %s", layout, disk.Label)
			}
		}
		if strings.Contains(all, "0.0 C") || !strings.Contains(all, "--") {
			t.Fatalf("missing readings rendered as zero: %s", all)
		}
	}
	for _, layout := range []string{"compact", "large", "disks", "pages"} {
		cfg := Defaults()
		cfg.Layout = layout
		cfg.ShowIP = false
		cfg.ShowDisks = false
		for page := 0; page < 10; page++ {
			for _, text := range Compose(cfg, data, page) {
				if strings.Contains(text.Value, "192.") || strings.Contains(text.Value, "DISK") || strings.Contains(text.Value, "HDD") || strings.Contains(text.Value, "sd") {
					t.Fatalf("hidden reading: %+v", text)
				}
			}
		}
	}
	cfg := Defaults()
	cfg.Layout = "large"
	cpu := 43.5
	data.CPU = &cpu
	scene := Compose(cfg, data, 0)
	if scene[1].Scale != 2 || scene[1].Value != "CPU 43.5C" {
		t.Fatalf("large font missing: %+v", scene)
	}
	cfg.Layout = "compact"
	if len(Compose(cfg, data, 0)) != 5 {
		t.Fatal("overview missing fifth row")
	}
}

func TestOldLayoutsNormalizeToLarge(t *testing.T) {
	for _, layout := range []string{"compact", "disks", "pages", "storage"} {
		cfg := Defaults()
		cfg.Layout = layout
		cfg.Enabled = true
		cfg.ShowIP, cfg.ShowCPU, cfg.ShowDisks = false, false, false
		cfg.Brightness = 5
		cfg.NormalizeLayout()
		if cfg.Layout != "large" || cfg.Brightness != 5 || !cfg.ShowIP || cfg.Validate() != nil {
			t.Fatal(cfg)
		}
	}
}
