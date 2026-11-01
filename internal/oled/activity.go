package oled

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

const ActivityPath = "/run/panasms-core/oled.json"

type Task struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Target    string    `json:"target,omitempty"`
	State     string    `json:"state"`
	Percent   *float64  `json:"percent,omitempty"`
	Remaining *float64  `json:"remaining,omitempty"`
	Started   time.Time `json:"started"`
}
type Event struct {
	ID       string    `json:"id"`
	Revision string    `json:"revision"`
	Kind     string    `json:"kind"`
	Target   string    `json:"target,omitempty"`
	Severity string    `json:"severity"`
	Active   bool      `json:"active"`
	At       time.Time `json:"at"`
}
type Volume struct {
	Name      string   `json:"name"`
	Available *float64 `json:"available,omitempty"`
}
type ArrayStatus struct {
	Name  string `json:"name"`
	State string `json:"state"`
}
type Activity struct {
	ObservedAt time.Time     `json:"observedAt"`
	StorageOK  bool          `json:"storageOK"`
	Arrays     []ArrayStatus `json:"arrays"`
	Volumes    []Volume      `json:"volumes"`
	Tasks      []Task        `json:"tasks"`
	Events     []Event       `json:"events"`
}

func WriteActivity(path string, activity Activity) error { return atomicJSON(path, activity) }
func ReadActivity(path string, now time.Time) (Activity, bool) {
	raw, err := os.ReadFile(path)
	var a Activity
	if err != nil || len(raw) > 256*1024 || json.Unmarshal(raw, &a) != nil {
		return a, false
	}
	age := now.Sub(a.ObservedAt)
	return a, age >= 0 && age < 30*time.Second
}
func validPercent(p *float64) bool {
	return p != nil && !math.IsNaN(*p) && !math.IsInf(*p, 0) && *p >= 0 && *p <= 100
}

// Display selection is independent of the producer's polling and event timestamps.
type ActivityDisplay struct {
	seen         map[string]string
	pending      []Event
	current      *Event
	until        time.Time
	page         int
	pageAt       time.Time
	network      string
	networkKnown bool
	raidTasks    map[string]Task
}

func (d *ActivityDisplay) Scene(cfg Settings, data Snapshot, a Activity, fresh bool, now time.Time) []Text {
	if d.seen == nil {
		d.seen = map[string]string{}
	}
	if d.pageAt.IsZero() {
		d.pageAt = now
	}
	if cfg.ShowEvents {
		if d.networkKnown && data.IP != d.network {
			kind := "network-ready"
			severity := "info"
			if data.IP == "" {
				kind = "network-lost"
				severity = "warning"
			}
			d.enqueue(Event{ID: "network", Revision: now.String(), Kind: kind, Severity: severity, At: now})
		}
		d.network = data.IP
		d.networkKnown = true
	}
	if fresh && cfg.ShowEvents {
		seen := map[string]string{}
		events := append([]Event(nil), a.Events...)
		sort.SliceStable(events, func(i, j int) bool { return events[i].At.Before(events[j].At) })
		for _, e := range events {
			seen[e.ID] = e.Revision
			age := now.Sub(e.At)
			if d.seen[e.ID] != e.Revision && ((age >= 0 && age < 2*time.Minute) || (e.Active && (e.Severity == "critical" || e.Severity == "error"))) {
				d.enqueue(e)
			}
		}
		d.seen = seen
		if a.StorageOK {
			current := map[string]Task{}
			for _, t := range a.Tasks {
				if strings.HasPrefix(t.ID, "raid:") {
					current[t.ID] = t
				}
			}
			for id, t := range d.raidTasks {
				if _, exists := current[id]; !exists {
					for _, ar := range a.Arrays {
						if ar.Name == t.Target && ar.State == "healthy" {
							d.enqueue(Event{ID: id + ":done", Kind: "raid-done", Target: t.Target, Severity: "success", At: now})
						}
					}
				}
			}
			d.raidTasks = current
		}
	}
	if !cfg.ShowEvents {
		d.current = nil
		d.pending = nil
	}
	if d.current != nil && !now.Before(d.until) {
		d.current = nil
		d.pageAt = now
	}
	if d.current == nil && len(d.pending) > 0 {
		e := d.pending[0]
		d.pending = d.pending[1:]
		d.current = &e
		d.until = now.Add(time.Duration(cfg.EventSeconds) * time.Second)
	}
	if d.current != nil {
		e := *d.current
		return rows([]string{label(cfg.Language, e.Severity), label(cfg.Language, e.Kind), short(label(cfg.Language, e.Target), 20), label(cfg.Language, "details-web")}, 2, 15)
	}
	if now.Sub(d.pageAt) >= time.Duration(cfg.PageSeconds)*time.Second {
		d.page++
		d.pageAt = now
	}
	if !fresh {
		scene := Compose(cfg, data, d.page)
		if cfg.ShowTasks || cfg.ShowEvents || cfg.Layout == "storage" || cfg.Layout == "pages" {
			state := "status-unavailable"
			if data.BootSeconds > 0 && data.BootSeconds < 120 {
				state = "starting-services"
			}
			return rows([]string{label(cfg.Language, state), label(cfg.Language, "waiting-data"), "IP " + short(data.IP, 17), "CPU " + temperature(data.CPU)}, 2, 15)
		}
		return scene
	}
	tasks := a.Tasks
	if cfg.ShowTasks && len(tasks) > 0 {
		// Active problems remain visible between task pages after their event expires.
		var problems []Event
		if cfg.ShowEvents {
			problems = activeProblems(a)
		}
		index := d.page % (len(tasks) + len(problems))
		if index >= len(tasks) {
			return eventPage(cfg, problems[index-len(tasks)])
		}
		return taskPage(cfg, tasks[index], index, len(tasks), now)
	}
	if problems := activeProblems(a); cfg.ShowEvents && len(problems) > 0 && d.page%2 == 1 {
		return eventPage(cfg, problems[(d.page/2)%len(problems)])
	}
	if cfg.Layout == "storage" {
		return storagePage(cfg, a, d.page)
	}
	if cfg.Layout == "pages" && d.page%2 == 1 {
		return storagePage(cfg, a, d.page/2)
	}
	if cfg.Layout == "pages" {
		return Compose(cfg, data, d.page/2)
	}
	return Compose(cfg, data, d.page)
}
func activeProblems(a Activity) []Event {
	var result []Event
	for _, e := range a.Events {
		if e.Active {
			result = append(result, e)
		}
	}
	return result
}
func (d *ActivityDisplay) enqueue(e Event) {
	if d.current != nil && d.current.Kind == e.Kind && d.current.Target == e.Target {
		return
	}
	for i, p := range d.pending {
		if p.ID == e.ID || (p.Kind == e.Kind && p.Target == e.Target) {
			d.pending[i] = e
			return
		}
	}
	if e.Severity == "critical" {
		if d.current != nil {
			d.pending = append([]Event{*d.current}, d.pending...)
			d.current = nil
		}
		d.pending = append([]Event{e}, d.pending...)
	} else {
		d.pending = append(d.pending, e)
	}
	if len(d.pending) > 20 {
		d.pending = d.pending[:20]
	}
}
func eventPage(cfg Settings, e Event) []Text {
	return rows([]string{label(cfg.Language, "attention"), label(cfg.Language, e.Kind), short(label(cfg.Language, e.Target), 20), label(cfg.Language, "details-web")}, 2, 15)
}
func taskPage(cfg Settings, t Task, index, total int, now time.Time) []Text {
	headline := label(cfg.Language, t.Kind)
	if total > 1 {
		headline = short(headline, 14) + fmt.Sprintf(" %d/%d", index+1, total)
	}
	scene := rows([]string{headline, short(t.Target, 20)}, 2, 11)
	value := label(cfg.Language, t.State)
	if validPercent(t.Percent) && t.State == "running" {
		value = fmt.Sprintf("%.0f%%", *t.Percent)
	}
	scene = append(scene, fitted(value, 26, 2))
	detail := label(cfg.Language, "working")
	if t.Remaining != nil && *t.Remaining >= 0 && !math.IsInf(*t.Remaining, 0) && !math.IsNaN(*t.Remaining) {
		detail = fmt.Sprintf("~ %.0f %s", math.Ceil(*t.Remaining/60), label(cfg.Language, "min-left"))
	} else if !t.Started.IsZero() && !now.Before(t.Started) {
		detail = fmt.Sprintf("%s %dm", label(cfg.Language, "elapsed"), int(now.Sub(t.Started).Minutes()))
	}
	scene = append(scene, Text{short(detail, 20), 2, 53, 1})
	if validPercent(t.Percent) && t.State == "running" {
		scene = append(scene, Text{strings.Repeat("=", int(*t.Percent/5)) + strings.Repeat("-", 20-int(*t.Percent/5)), 2, 44, 1})
	}
	return scene
}
func storagePage(cfg Settings, a Activity, page int) []Text {
	if !a.StorageOK {
		return rows([]string{label(cfg.Language, "storage"), label(cfg.Language, "status-unavailable")}, 2, 15)
	}
	pages := len(a.Arrays) + len(a.Volumes)
	if pages == 0 {
		return rows([]string{label(cfg.Language, "storage"), label(cfg.Language, "no-storage")}, 2, 15)
	}
	index := page % pages
	if index < len(a.Arrays) {
		ar := a.Arrays[index]
		return rows([]string{"RAID " + short(ar.Name, 15), label(cfg.Language, ar.State), fmt.Sprintf("%d/%d", index+1, pages)}, 2, 18)
	}
	v := a.Volumes[index-len(a.Arrays)]
	free := "--"
	if v.Available != nil {
		free = formatBytes(*v.Available)
	}
	return rows([]string{label(cfg.Language, "storage") + " " + short(v.Name, 10), label(cfg.Language, "free"), free, fmt.Sprintf("%d/%d", index+1, pages)}, 2, 15)
}
func formatBytes(n float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", n, units[i])
}
