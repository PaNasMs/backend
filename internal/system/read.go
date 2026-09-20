package system

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type User struct {
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Device   string   `json:"device"`
	UUID     string   `json:"uuid"`
	Size     uint64   `json:"size"`
	UID      int      `json:"uid"`
	GID      int      `json:"gid"`
	Home     string   `json:"home"`
	Shell    string   `json:"shell"`
	Category string   `json:"category"`
	Groups   []string `json:"groups"`
}
type Group struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}
type Accounts struct {
	Users  []User  `json:"users"`
	Groups []Group `json:"groups"`
}

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(c, name, args...).Output()
}
func AccountsRead(ctx context.Context) (Accounts, error) {
	a := Accounts{Users: []User{}, Groups: []Group{}}
	raw, e := command(ctx, "/usr/bin/getent", "passwd")
	if e != nil {
		return a, e
	}
	gr, e := command(ctx, "/usr/bin/getent", "group")
	if e != nil {
		return a, e
	}
	for _, l := range strings.Split(strings.TrimSpace(string(gr)), "\n") {
		p := strings.Split(l, ":")
		if len(p) != 4 {
			continue
		}
		gid, e := strconv.Atoi(p[2])
		if e != nil {
			continue
		}
		members := []string{}
		if p[3] != "" {
			members = strings.Split(p[3], ",")
		}
		a.Groups = append(a.Groups, Group{p[0], gid, members})
	}
	min, max := 1000, 60000
	if data, e := os.ReadFile("/etc/login.defs"); e == nil {
		for _, l := range strings.Split(string(data), "\n") {
			p := strings.Fields(l)
			if len(p) >= 2 {
				v, e := strconv.Atoi(p[1])
				if e == nil {
					switch p[0] {
					case "UID_MIN":
						min = v
					case "UID_MAX":
						max = v
					}
				}
			}
		}
	}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		p := strings.Split(l, ":")
		if len(p) != 7 {
			continue
		}
		uid, e := strconv.Atoi(p[2])
		if e != nil {
			continue
		}
		gid, e := strconv.Atoi(p[3])
		if e != nil {
			continue
		}
		u := User{Username: p[0], Name: strings.Split(p[4], ",")[0], UID: uid, GID: gid, Home: p[5], Shell: p[6], Category: "service", Groups: []string{}}
		if uid >= min && uid <= max && uid != 65534 {
			u.Category = "user"
		}
		for i := range a.Groups {
			g := &a.Groups[i]
			member := g.GID == gid
			listed := false
			for _, n := range g.Members {
				if n == u.Username {
					member = true
					listed = true
				}
			}
			if member {
				u.Groups = append(u.Groups, g.Name)
				if !listed {
					g.Members = append(g.Members, u.Username)
				}
				if g.Name == "sudo" && u.Category == "user" {
					u.Category = "admin"
				}
			}
		}
		a.Users = append(a.Users, u)
	}
	return a, nil
}

type Array struct {
	ReshapePending bool              `json:"reshapePending"`
	Missing        int               `json:"missing"`
	MemberStates   map[string]string `json:"memberStates"`
	SyncPercent    *float64          `json:"syncPercent,omitempty"`
	SyncSpeed      *float64          `json:"syncSpeed,omitempty"`
	SyncRemaining  *float64          `json:"syncRemaining,omitempty"`
	Name           string            `json:"name"`
	Device         string            `json:"device"`
	UUID           string            `json:"uuid"`
	Size           uint64            `json:"size"`
	Level          string            `json:"level"`
	State          string            `json:"state"`
	Degraded       string            `json:"degraded"`
	Members        []string          `json:"members"`
	Sync           string            `json:"sync"`
	Progress       string            `json:"progress"`
}
type Storage struct {
	Devices    []map[string]any `json:"devices"`
	Mounts     []map[string]any `json:"mounts"`
	Arrays     []Array          `json:"arrays"`
	ObservedAt time.Time        `json:"observedAt"`
}

func text(path string) string {
	b, e := os.ReadFile(path)
	if e != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
func StorageRead(ctx context.Context) (Storage, error) {
	s := Storage{Devices: []map[string]any{}, Mounts: []map[string]any{}, Arrays: []Array{}, ObservedAt: time.Now().UTC()}
	raw, e := command(ctx, "/usr/bin/lsblk", "--json", "--bytes", "--output", "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,FSTYPE,UUID,MOUNTPOINTS,PKNAME,ROTA,MAJ:MIN,LABEL")
	if e != nil {
		return s, e
	}
	var d struct {
		Devices []map[string]any `json:"blockdevices"`
	}
	if e = json.Unmarshal(raw, &d); e != nil {
		return s, e
	}
	for _, device := range d.Devices {
		name, _ := device["kname"].(string)
		if strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "zram") || strings.HasPrefix(name, "loop") {
			continue
		}
		s.Devices = append(s.Devices, device)
	}
	raw, e = command(ctx, "/usr/bin/findmnt", "--task", "1", "--json", "--bytes", "--list", "--real", "--output", "SOURCE,TARGET,FSTYPE,OPTIONS,MAJ:MIN,SIZE,USED,AVAIL")
	if e != nil {
		return s, e
	}
	var m struct {
		Mounts []map[string]any `json:"filesystems"`
	}
	if e = json.Unmarshal(raw, &m); e != nil {
		return s, e
	}
	s.Mounts = m.Mounts
	addGeometry(s.Devices)
	applyHostMounts(s.Devices, s.Mounts)
	mdstat := text("/proc/mdstat")
	dirs, _ := filepath.Glob("/sys/block/md*/md")
	for _, dir := range dirs {
		a := Array{Name: filepath.Base(filepath.Dir(dir)), Level: text(dir + "/level"), State: text(dir + "/array_state"), Degraded: text(dir + "/degraded"), Sync: text(dir + "/sync_action"), Progress: text(dir + "/sync_completed"), Members: []string{}}
		members, _ := filepath.Glob(filepath.Dir(dir) + "/slaves/*")
		for _, p := range members {
			a.Members = append(a.Members, filepath.Base(p))
		}
		a.MemberStates = map[string]string{}
		slots := map[int]bool{}
		entries, _ := filepath.Glob(dir + "/dev-*")
		for _, entry := range entries {
			member := strings.TrimPrefix(filepath.Base(entry), "dev-")
			state := text(entry + "/state")
			slot, err := strconv.Atoi(text(entry + "/slot"))
			if err == nil && slot >= 0 && !strings.Contains(state, "faulty") {
				slots[slot] = true
				if !strings.Contains(state, "in_sync") && a.Sync == "recover" {
					state = "recovering"
				}
			}
			a.MemberStates[member] = state
		}
		expected, _ := strconv.Atoi(text(dir + "/raid_disks"))
		a.Missing = max(0, expected-len(slots))
		readMDProgress(&a, mdstat)
		readMDReshape(&a, dir)
		a.Device = "/dev/" + a.Name
		a.UUID = text(dir + "/uuid")
		sectors, _ := strconv.ParseUint(text(filepath.Dir(dir)+"/size"), 10, 64)
		a.Size = sectors * 512
		aliases, _ := filepath.Glob("/dev/md/*")
		for _, alias := range aliases {
			if target, e := filepath.EvalSymlinks(alias); e == nil && target == a.Device {
				a.Name = filepath.Base(alias)
				break
			}
		}
		s.Arrays = append(s.Arrays, a)
	}
	return s, nil
}

var mdProgress = regexp.MustCompile(`(?:recovery|resync|reshape|check|repair)\s*=\s*([0-9.]+)%`)
var mdFinish = regexp.MustCompile(`finish=([0-9.]+)min`)
var mdSpeed = regexp.MustCompile(`speed=([0-9.]+)K/sec`)

func readMDProgress(a *Array, mdstat string) {
	if a.Sync == "idle" || a.Sync == "frozen" {
		return
	}
	active := false
	for _, line := range strings.Split(mdstat, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == ":" {
			active = fields[0] == a.Name
		}
		if !active {
			continue
		}
		for _, value := range []struct {
			pattern *regexp.Regexp
			target  **float64
			scale   float64
		}{
			{mdProgress, &a.SyncPercent, 1}, {mdFinish, &a.SyncRemaining, 60}, {mdSpeed, &a.SyncSpeed, 1024},
		} {
			if m := value.pattern.FindStringSubmatch(line); len(m) == 2 {
				n, err := strconv.ParseFloat(m[1], 64)
				if err == nil {
					n *= value.scale
					*value.target = &n
				}
			}
		}
	}
}

type Metrics struct {
	Disks           map[string]Transfer `json:"disks"`
	Network         map[string]Transfer `json:"network"`
	SystemTotal     uint64              `json:"systemTotal"`
	SystemAvailable uint64              `json:"systemAvailable"`
	Hostname        string              `json:"hostname"`
	CPU             *float64            `json:"cpu"`
	MemoryTotal     uint64              `json:"memoryTotal"`
	MemoryUsed      uint64              `json:"memoryUsed"`
	Uptime          float64             `json:"uptime"`
	CPUTemperature  *float64            `json:"cpuTemperature"`
	CPUFanPercent   *int                `json:"cpuFanPercent"`
	CPUFanRPM       *int                `json:"cpuFanRpm"`
	ObservedAt      time.Time           `json:"observedAt"`
}
type Collector struct {
	diskCounters, netCounters map[string]counters
	lastSample                time.Time
	mu                        sync.Mutex
	lastTotal, lastIdle       uint64
}

func (c *Collector) Read() (Metrics, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := Metrics{ObservedAt: time.Now().UTC()}
	m.Hostname, _ = os.Hostname()
	c.rates(&m)
	hwmons, _ := filepath.Glob("/sys/class/hwmon/hwmon*")
	for _, hw := range hwmons {
		if text(hw+"/name") == "pwmfan" {
			if pwm, err := strconv.Atoi(text(hw + "/pwm1")); err == nil && pwm >= 0 && pwm <= 255 {
				percent := (pwm*100 + 127) / 255
				m.CPUFanPercent = &percent
			}
			if rpm, err := strconv.Atoi(text(hw + "/fan1_input")); err == nil && rpm >= 0 {
				m.CPUFanRPM = &rpm
			}
		}
	}

	raw, e := os.ReadFile("/proc/stat")
	if e != nil {
		return m, e
	}
	p := strings.Fields(strings.SplitN(string(raw), "\n", 2)[0])
	if len(p) < 5 {
		return m, errors.New("invalid cpu counters")
	}
	var total, idle uint64
	for i, v := range p[1:] {
		if i >= 8 {
			break
		}
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 3 || i == 4 {
			idle += n
		}
	}
	if c.lastTotal > 0 && total > c.lastTotal && idle >= c.lastIdle {
		busy := 100 * (1 - float64(idle-c.lastIdle)/float64(total-c.lastTotal))
		if busy >= 0 && busy <= 100 {
			m.CPU = &busy
		}
	}
	c.lastTotal, c.lastIdle = total, idle
	raw, e = os.ReadFile("/proc/meminfo")
	if e != nil {
		return m, e
	}
	var available uint64
	for _, l := range strings.Split(string(raw), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			m.MemoryTotal = v * 1024
		case "MemAvailable:":
			available = v * 1024
		}
	}
	if available <= m.MemoryTotal {
		m.MemoryUsed = m.MemoryTotal - available
	}
	up := strings.Fields(text("/proc/uptime"))
	if len(up) > 0 {
		m.Uptime, _ = strconv.ParseFloat(up[0], 64)
	}
	zones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*")
	for _, z := range zones {
		t := text(z + "/type")
		if t == "cpu-thermal" || t == "x86_pkg_temp" {
			n, e := strconv.ParseFloat(text(z+"/temp"), 64)
			if e == nil {
				v := n / 1000
				m.CPUTemperature = &v
			}
			break
		}
	}
	return m, nil
}
func Watch(ctx context.Context, notify func(string)) {
	go func() {
		for ctx.Err() == nil {
			cmd := exec.CommandContext(ctx, "/usr/bin/udevadm", "monitor", "--udev", "--subsystem-match=block")
			pipe, e := cmd.StdoutPipe()
			if e == nil {
				e = cmd.Start()
			}
			if e == nil {
				buf := make([]byte, 8192)
				for {
					n, e := pipe.Read(buf)
					if n > 0 {
						notify("storage.changed")
					}
					if e != nil {
						break
					}
				}
				cmd.Wait()
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
	}()
	go func() {
		file, err := os.Open("/proc/1/mounts")
		if err != nil {
			return
		}
		defer file.Close()
		clear := func() {
			file.Seek(0, 0)
			data := make([]byte, 8192)
			for {
				_, e := file.Read(data)
				if e != nil {
					break
				}
			}
		}
		clear()
		for ctx.Err() == nil {
			fds := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLPRI | unix.POLLERR}}
			_, err := unix.Poll(fds, 1000)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return
			}
			if fds[0].Revents != 0 {
				clear()
				notify("storage.changed")
			}
		}
	}()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	last := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			state := text("/proc/mdstat")
			if state != last {
				last = state
				notify("storage.changed")
			}
		}
	}
}
func ValidatePreferences(theme string, layouts map[string][]string) error {
	if layouts == nil {
		return errors.New("layouts must be an object")
	}
	if theme != "dark" && theme != "light" {
		return fmt.Errorf("unknown theme")
	}
	allowed := map[string]bool{"cpu": true, "memory": true, "cooling": true, "system": true, "users": true, "storage": true}
	for mode, tiles := range layouts {
		if mode != "wide" && mode != "medium" && mode != "mobile" {
			return errors.New("unknown layout")
		}
		if len(tiles) != len(allowed) {
			return errors.New("invalid tile count")
		}
		seen := map[string]bool{}
		for _, t := range tiles {
			if !allowed[t] || seen[t] {
				return errors.New("invalid tile")
			}
			seen[t] = true
		}
	}
	return nil
}

func applyHostMounts(devices, mounts []map[string]any) {
	var apply func(map[string]any)
	apply = func(device map[string]any) {
		points := []string{}
		for _, mount := range mounts {
			if id, ok := device["maj:min"].(string); ok && id != "" && mount["maj:min"] == id {
				if target, ok := mount["target"].(string); ok {
					points = append(points, target)
				}
			}
		}
		device["mountpoints"] = points
		if children, ok := device["children"].([]any); ok {
			for _, child := range children {
				if d, ok := child.(map[string]any); ok {
					apply(d)
				}
			}
		}
	}
	for _, device := range devices {
		apply(device)
	}
}

func addGeometry(devices []map[string]any) {
	for _, device := range devices {
		name, _ := device["kname"].(string)
		if start, err := strconv.ParseUint(text("/sys/class/block/"+name+"/start"), 10, 64); err == nil {
			device["start"] = start * 512
		}
		if children, ok := device["children"].([]any); ok {
			for _, child := range children {
				if d, ok := child.(map[string]any); ok {
					addGeometry([]map[string]any{d})
				}
			}
		}
	}
}

func readMDReshape(a *Array, dir string) {
	position, err := strconv.ParseUint(text(dir+"/reshape_position"), 10, 64)
	if err != nil {
		return
	}
	a.ReshapePending = true
	if a.SyncPercent != nil {
		return
	}
	// reshape_position is in sectors; component_size is in KiB.
	if a.Level != "raid5" && a.Level != "raid6" {
		return
	}
	if text(dir+"/reshape_direction") == "backwards" {
		return
	}
	component, err := strconv.ParseUint(text(dir+"/component_size"), 10, 64)
	if err != nil || component == 0 {
		return
	}
	fields := strings.Fields(text(dir + "/raid_disks"))
	if len(fields) == 0 {
		return
	}
	disks, err := strconv.Atoi(fields[0])
	parity := 1
	if a.Level == "raid6" {
		parity = 2
	}
	if err != nil || disks <= parity {
		return
	}
	percent := min(100.0, float64(position)/(2*float64(component))/float64(disks-parity)*100)
	a.SyncPercent = &percent
}
