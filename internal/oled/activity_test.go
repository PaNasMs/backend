package oled

import (
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sceneText(scene []Text) string {
	var s []string
	for _, t := range scene {
		s = append(s, t.Value)
	}
	return strings.Join(s, "\n")
}
func TestEventDurationDeduplicationAndReturn(t *testing.T) {
	now := time.Now()
	cfg := Defaults()
	data := Snapshot{Host: "NAS"}
	a := Activity{ObservedAt: now, StorageOK: true}
	d := &ActivityDisplay{}
	baseline := sceneText(d.Scene(cfg, data, a, true, now))
	e := Event{ID: "device:1", Revision: "1", Kind: "device-connected", At: now, Severity: "info"}
	a.Events = []Event{e}
	if text := sceneText(d.Scene(cfg, data, a, true, now)); !strings.Contains(text, "DRIVE CONNECTED") {
		t.Fatal(text)
	}
	if text := sceneText(d.Scene(cfg, data, a, true, now.Add(19*time.Second))); !strings.Contains(text, "DRIVE CONNECTED") {
		t.Fatal("expired early", text)
	}
	if text := sceneText(d.Scene(cfg, data, a, true, now.Add(20*time.Second))); text != baseline {
		t.Fatal("did not restore page", text)
	}
	if text := sceneText(d.Scene(cfg, data, a, true, now.Add(21*time.Second))); strings.Contains(text, "DRIVE CONNECTED") {
		t.Fatal("replayed", text)
	}
}
func TestCriticalPreemptsAndProblemsPersist(t *testing.T) {
	now := time.Now()
	cfg := Defaults()
	d := &ActivityDisplay{}
	a := Activity{StorageOK: true, Events: []Event{{ID: "a", Revision: "1", Kind: "device-connected", Severity: "info", At: now}}}
	d.Scene(cfg, Snapshot{}, a, true, now)
	a.Events = append(a.Events, Event{ID: "b", Revision: "1", Kind: "raid-problem", Severity: "critical", Active: true, At: now})
	if text := sceneText(d.Scene(cfg, Snapshot{}, a, true, now.Add(time.Second))); !strings.Contains(text, "CHECK RAID") {
		t.Fatal(text)
	}
	for i := 0; i < 10; i++ {
		d.Scene(cfg, Snapshot{}, a, true, now.Add(time.Duration(i+2)*time.Second))
	}
	if len(d.pending) != 1 {
		t.Fatal("duplicate events", len(d.pending))
	}
	d.Scene(cfg, Snapshot{}, a, true, now.Add(22*time.Second))
	d.Scene(cfg, Snapshot{}, a, true, now.Add(43*time.Second))
	if text := sceneText(d.Scene(cfg, Snapshot{}, a, true, now.Add(50*time.Second))); !strings.Contains(text, "CHECK RAID") {
		t.Fatal("problem disappeared", text)
	}
	cfg.ShowEvents = false
	if text := sceneText(d.Scene(cfg, Snapshot{}, a, true, now.Add(51*time.Second))); strings.Contains(text, "CHECK RAID") {
		t.Fatal(text)
	}
}
func TestTasksStorageAndStaleData(t *testing.T) {
	now := time.Now()
	p := 47.0
	remaining := 3600.0
	free := float64(2 << 40)
	a := Activity{ObservedAt: now, StorageOK: true, Arrays: []ArrayStatus{{"md127", "healthy"}}, Volumes: []Volume{{"md127", &free}}, Tasks: []Task{{ID: "1", Kind: "raid-recover", State: "running", Percent: &p, Remaining: &remaining}, {ID: "2", Kind: "upload", State: "running", Started: now.Add(-time.Minute)}}}
	cfg := Defaults()
	cfg.ShowEvents = false
	d := &ActivityDisplay{}
	text := sceneText(d.Scene(cfg, Snapshot{}, a, true, now))
	if !strings.Contains(text, "47%") || !strings.Contains(text, "1/2") {
		t.Fatal(text)
	}
	text = sceneText(d.Scene(cfg, Snapshot{}, a, true, now.Add(6*time.Second)))
	if !strings.Contains(text, "UPLOAD") || strings.Contains(text, "%") {
		t.Fatal(text)
	}
	text = sceneText(d.Scene(cfg, Snapshot{}, a, false, now.Add(7*time.Second)))
	if strings.Contains(text, "47%") || !strings.Contains(text, "UNAVAILABLE") {
		t.Fatal(text)
	}
	cfg.ShowTasks = false
	cfg.Layout = "storage"
	if text = sceneText(d.Scene(cfg, Snapshot{}, a, true, now.Add(8*time.Second))); !strings.Contains(text, "2.0 TiB") {
		t.Fatal(text)
	}
	a.StorageOK = false
	if text = sceneText(d.Scene(cfg, Snapshot{}, a, true, now.Add(9*time.Second))); !strings.Contains(text, "UNAVAILABLE") {
		t.Fatal(text)
	}
}
func TestActivityFreshnessAndSettingsMigration(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "feed.json")
	for _, age := range []time.Duration{0, 29 * time.Second, 30 * time.Second, -time.Second} {
		if err := WriteActivity(path, Activity{ObservedAt: now.Add(-age)}); err != nil {
			t.Fatal(err)
		}
		_, fresh := ReadActivity(path, now)
		if fresh != (age >= 0 && age < 30*time.Second) {
			t.Fatal(age, fresh)
		}
	}
	cfg, err := readConfig(filepath.Join(t.TempDir(), "missing"))
	if err != nil || cfg.EventSeconds != 20 || !cfg.ShowTasks || !cfg.ShowEvents || cfg.Language != "en" {
		t.Fatal(cfg, err)
	}
	for _, v := range []int{14, 61} {
		cfg.EventSeconds = v
		if cfg.Validate() == nil {
			t.Fatal(v)
		}
	}
	cfg = Defaults()
	cfg.Layout = "storage"
	cfg.Enabled = true
	cfg.ShowIP = false
	cfg.ShowCPU = false
	cfg.ShowDisks = false
	cfg.NormalizeLayout()
	if err = cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestLocalizedActivityGlyphsAndLayout(t *testing.T) {
	for key, translations := range labels {
		for _, value := range translations {
			for _, r := range strings.ToUpper(value) {
				if _, ok := glyphs[r]; !ok {
					t.Fatalf("missing glyph %q in %s", r, key)
				}
			}
		}
	}
	p := 99.0
	now := time.Now()
	for _, lang := range []string{"en", "ru", "uk"} {
		cfg := Defaults()
		cfg.Language = lang
		for _, task := range []Task{{Kind: "raid-recover", State: "running", Percent: &p}, {Kind: "upload", State: "paused"}} {
			scene := taskPage(cfg, task, 0, 3, now)
			for _, v := range scene {
				if v.X+(len([]rune(v.Value))*6-1)*v.Scale > 125 || v.Y+7*v.Scale > 62 {
					t.Fatal("clipped", v)
				}
			}
		}
	}
	for _, n := range []float64{math.NaN(), math.Inf(1), -1, 101} {
		if validPercent(&n) {
			t.Fatal(n)
		}
	}
}

func TestRAIDCompletionOnlyWithConfirmedHealthyArray(t *testing.T) {
	now := time.Now()
	cfg := Defaults()
	a := Activity{StorageOK: true, Arrays: []ArrayStatus{{"md0", "degraded"}}, Tasks: []Task{{ID: "raid:md0", Kind: "raid-recover", Target: "md0", State: "running"}}}
	d := &ActivityDisplay{}
	d.Scene(cfg, Snapshot{}, a, true, now)
	a.StorageOK = false
	a.Tasks = nil
	if text := sceneText(d.Scene(cfg, Snapshot{}, a, true, now.Add(time.Second))); strings.Contains(text, "FINISHED") {
		t.Fatal(text)
	}
	a.StorageOK = true
	a.Arrays[0].State = "healthy"
	if text := sceneText(d.Scene(cfg, Snapshot{}, a, true, now.Add(2*time.Second))); !strings.Contains(text, "FINISHED") {
		t.Fatal(text)
	}
}

func TestProblemsDoNotStarveStorageRotation(t *testing.T) {
	now := time.Now()
	free := 1024.0
	cfg := Defaults()
	cfg.Layout = "pages"
	cfg.ShowTasks = false
	a := Activity{StorageOK: true, Arrays: []ArrayStatus{{"md0", "degraded"}}, Volumes: []Volume{{"sda", &free}}, Events: []Event{{ID: "problem", Revision: "1", Kind: "raid-problem", Severity: "warning", Active: true, At: now.Add(-time.Hour)}}}
	d := &ActivityDisplay{}
	text := ""
	for i := 0; i < 12; i++ {
		text += sceneText(d.Scene(cfg, Snapshot{IP: "192.168.1.100"}, a, true, now.Add(time.Duration(i*cfg.PageSeconds)*time.Second)))
	}
	for _, want := range []string{"DEGRADED", "FREE", "192.168.1.100", "ATTENTION"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s: %s", want, text)
		}
	}
}

func TestEventFramesOmitWebUIFooter(t *testing.T) {
	for _, language := range []string{"en", "ru", "uk"} {
		cfg := Defaults()
		cfg.Language = language
		event := Event{ID: "test", Revision: "1", Kind: "smart", Severity: "warning", Active: true, At: time.Now()}
		d := &ActivityDisplay{}
		scene := d.Scene(cfg, Snapshot{}, Activity{Events: []Event{event}}, true, event.At)
		if len(scene) != 3 || scene[1].Value != label(language, "smart") || d.current == nil || len(eventPage(cfg, event)) != 3 {
			t.Fatalf("unexpected footer: %+v", scene)
		}
	}
}
