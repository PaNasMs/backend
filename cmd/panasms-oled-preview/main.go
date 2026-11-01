package main

import (
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
	"panasms.local/backend/internal/oled"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Usage: panasms-oled-preview OUTPUT_DIRECTORY")
	}
	if err := os.MkdirAll(os.Args[1], 0755); err != nil {
		log.Fatal(err)
	}
	cpu, a, b, c, d := 43.5, 37.0, 36.0, 38.0, 35.0
	data := oled.Snapshot{Host: "PANASMS", IP: "192.168.1.100", CPU: &cpu, Disks: []oled.Disk{{Label: "SDA", Temperature: &a}, {Label: "SDB", Temperature: &b}, {Label: "SDC", Temperature: &c}, {Label: "SDD", Temperature: &d}}, Uptime: "12D 03:45"}
	for _, layout := range []string{"compact", "large", "disks", "pages", "storage", "activity", "event", "activity-ru", "activity-uk"} {
		cfg := oled.Defaults()
		cfg.Layout = layout
		page := 0
		if layout == "pages" {
			page = 1
		}
		scene := oled.Compose(cfg, data, page)
		if layout == "storage" || layout == "activity" || layout == "event" || layout == "activity-ru" || layout == "activity-uk" {
			free := float64(2 << 40)
			percent := 47.0
			remaining := 8100.0
			activity := oled.Activity{StorageOK: true, Arrays: []oled.ArrayStatus{{Name: "md127", State: "healthy"}}, Volumes: []oled.Volume{{Name: "md127", Available: &free}}}
			if layout != "storage" {
				activity.Tasks = []oled.Task{{ID: "raid:md127", Kind: "raid-recover", Target: "md127", State: "running", Percent: &percent, Remaining: &remaining}}
			}
			if layout == "activity-ru" {
				cfg.Language = "ru"
			}
			if layout == "activity-uk" {
				cfg.Language = "uk"
			}
			if layout == "event" {
				activity.Events = []oled.Event{{ID: "device:1", Revision: "1", Kind: "device-connected", Severity: "info", At: time.Now()}}
			}
			display := &oled.ActivityDisplay{}
			scene = display.Scene(cfg, data, activity, true, time.Now())
		}
		frame := oled.RenderScene(scene, 0, 0)
		img := image.NewGray(image.Rect(0, 0, 128, 64))
		for y := 0; y < 64; y++ {
			for x := 0; x < 128; x++ {
				if frame[y/8*128+x]&(1<<uint(y%8)) != 0 {
					img.SetGray(x, y, color.Gray{Y: 255})
				}
			}
		}
		f, err := os.Create(filepath.Join(os.Args[1], layout+".png"))
		if err != nil {
			log.Fatal(err)
		}
		if err = png.Encode(f, img); err != nil {
			log.Fatal(err)
		}
		if err = f.Close(); err != nil {
			log.Fatal(err)
		}
	}
}
