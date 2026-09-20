package system

import (
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
	"time"
)

type Transfer struct {
	Read  float64 `json:"read"`
	Write float64 `json:"write"`
}
type counters struct{ a, b uint64 }

func (c *Collector) rates(m *Metrics) {
	now := time.Now()
	elapsed := now.Sub(c.lastSample).Seconds()
	m.Disks = map[string]Transfer{}
	m.Network = map[string]Transfer{}
	disk := map[string]counters{}
	raw, _ := os.ReadFile("/proc/diskstats")
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 14 {
			continue
		}
		a, e1 := strconv.ParseUint(f[5], 10, 64)
		b, e2 := strconv.ParseUint(f[9], 10, 64)
		if e1 == nil && e2 == nil {
			disk[f[2]] = counters{a * 512, b * 512}
		}
	}
	net := map[string]counters{}
	raw, _ = os.ReadFile("/proc/net/dev")
	for _, line := range strings.Split(string(raw), "\n") {
		p := strings.SplitN(line, ":", 2)
		if len(p) != 2 {
			continue
		}
		f := strings.Fields(p[1])
		if len(f) < 9 {
			continue
		}
		a, _ := strconv.ParseUint(f[0], 10, 64)
		b, _ := strconv.ParseUint(f[8], 10, 64)
		if strings.TrimSpace(p[0]) != "lo" {
			net[strings.TrimSpace(p[0])] = counters{a, b}
		}
	}
	fill := func(next, prev map[string]counters, out map[string]Transfer) {
		for key, v := range next {
			old, ok := prev[key]
			if ok && elapsed > 0 && v.a >= old.a && v.b >= old.b {
				out[key] = Transfer{float64(v.a-old.a) / elapsed, float64(v.b-old.b) / elapsed}
			}
		}
	}
	fill(disk, c.diskCounters, m.Disks)
	fill(net, c.netCounters, m.Network)
	c.diskCounters = disk
	c.netCounters = net
	c.lastSample = now
	var stat unix.Statfs_t
	if unix.Statfs("/", &stat) == nil {
		m.SystemTotal = stat.Blocks * uint64(stat.Bsize)
		m.SystemAvailable = stat.Bavail * uint64(stat.Bsize)
	}
}
