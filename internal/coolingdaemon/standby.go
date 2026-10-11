package coolingdaemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const sleepCapabilityPath = "/var/lib/panasms-cooling/sleep-reads.json"

type sleepCapability struct {
	Readable *bool     `json:"readable,omitempty"`
	Failures int       `json:"failures,omitempty"`
	RetryAt  time.Time `json:"retryAt,omitempty"`
}
type sleepCapabilities struct {
	Version int                        `json:"version"`
	Disks   map[string]sleepCapability `json:"disks"`
}
type standbyReader struct {
	cache    sleepCapabilities
	path     string
	command  func(context.Context, ...string) ([]byte, int, error)
	activity func(string) (string, error)
	now      func() time.Time
}

func newStandbyReader(path string) *standbyReader {
	cache := sleepCapabilities{Version: 2, Disks: map[string]sleepCapability{}}
	raw, err := os.ReadFile(path)
	if err == nil {
		var saved sleepCapabilities
		if json.Unmarshal(raw, &saved) == nil && saved.Version == 2 && saved.Disks != nil {
			cache = saved
		} else {
			// Old negative entries also included transient failures; retry them once.
			var legacy map[string]bool
			if json.Unmarshal(raw, &legacy) == nil {
				for disk, readable := range legacy {
					if readable {
						value := true
						cache.Disks[disk] = sleepCapability{Readable: &value}
					}
				}
			}
		}
	}
	return &standbyReader{cache: cache, path: path, command: smartCommand, activity: diskActivity, now: time.Now}
}

func smartCommand(ctx context.Context, args ...string) ([]byte, int, error) {
	sub, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(sub, "/usr/sbin/smartctl", args...).Output()
	if sub.Err() != nil {
		return raw, -1, sub.Err()
	}
	if e, ok := err.(*exec.ExitError); ok {
		return raw, e.ExitCode(), nil
	}
	return raw, 0, err
}

func diskActivity(path string) (string, error) {
	device, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	root := filepath.Join("/sys/class/block", filepath.Base(device))
	seq, err := os.ReadFile(filepath.Join(root, "diskseq"))
	if err != nil {
		return "", err
	}
	stat, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(stat))
	if len(fields) < 11 || fields[8] != "0" {
		return "", fmt.Errorf("disk I/O is in progress or unavailable")
	}
	return string(seq) + strings.Join(fields, ":"), nil
}

func (r *standbyReader) powerState(ctx context.Context, path string) (string, error) {
	raw, code, err := r.command(ctx, "-n", "standby,3,5", "-d", "ata", "-i", "-j", path)
	if err != nil {
		return "unknown", err
	}
	var result struct {
		Smartctl struct {
			Messages []struct {
				String string `json:"string"`
			} `json:"messages"`
		} `json:"smartctl"`
	}
	if err = json.Unmarshal(raw, &result); err != nil {
		return "unknown", err
	}
	if code == 3 {
		for _, message := range result.Smartctl.Messages {
			text := strings.ToUpper(message.String)
			if strings.Contains(text, "STANDBY") || strings.Contains(text, "SLEEP") {
				return "sleeping", nil
			}
		}
	}
	if code == 0 {
		return "active", nil
	}
	return "unknown", fmt.Errorf("power-state check failed (exit %d)", code)
}

func (r *standbyReader) save(path string, capability sleepCapability) {
	r.cache.Disks[path] = capability
	if err := atomicJSON(r.path, r.cache); err != nil {
		log.Printf("Cooling sensor %s: cannot save standby capability: %v", path, err)
	}
}

func (r *standbyReader) read(ctx context.Context, path string, row Disk) Disk {
	capability := r.cache.Disks[path]
	row.SleepReadable = capability.Readable
	if (capability.Readable != nil && !*capability.Readable) || r.now().Before(capability.RetryAt) {
		return row
	}
	retry := func() {
		capability.Failures = min(max(capability.Failures, 0)+1, 7)
		capability.RetryAt = r.now().Add(min(time.Minute*time.Duration(1<<capability.Failures), time.Hour))
		r.save(path, capability)
	}
	before, err := r.activity(path)
	if err != nil {
		retry()
		return row
	}
	state, err := r.powerState(ctx, path)
	if err != nil || state != "sleeping" {
		row = unknownDisk(path, fmt.Errorf("disk left standby or power state is unavailable"))
		retry()
		return row
	}
	raw, code, readErr := r.command(ctx, "-d", "ata", "-A", "-j", path)
	state, stateErr := r.powerState(ctx, path)
	after, activityErr := r.activity(path)
	if ctx.Err() != nil {
		return unknownDisk(path, ctx.Err())
	}
	temp := sleepTemperature(raw)
	succeeded := readErr == nil && code >= 0 && code&7 == 0 && temp != nil
	if stateErr != nil {
		row = unknownDisk(path, stateErr)
		retry()
		return row
	}
	if state != "sleeping" {
		// Only a successful probe with unchanged block I/O can establish incompatibility.
		// A concurrent application read, timeout or disconnect is inconclusive.
		row = unknownDisk(path, fmt.Errorf("disk left standby during temperature read; awaiting fresh sample"))
		if succeeded && activityErr == nil && before == after {
			value := false
			capability = sleepCapability{Readable: &value}
			r.save(path, capability)
			row.SleepReadable = &value
		} else {
			retry()
		}
		return row
	}
	if !succeeded || activityErr != nil || before != after {
		retry()
		return row
	}
	value := true
	if capability.Readable == nil || !*capability.Readable || capability.Failures != 0 {
		r.save(path, sleepCapability{Readable: &value})
	}
	now := float64(r.now().UnixNano()) / 1e9
	row.SleepReadable, row.Temperature, row.ObservedAt = &value, temp, &now
	row.SleepTemperature, row.Stale, row.SmartStale = true, false, true
	return row
}
