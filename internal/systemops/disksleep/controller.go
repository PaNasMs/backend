package disksleep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type sample struct {
	Counters [7]uint64 `json:"counters"`
	InFlight uint64    `json:"inFlight"`
}
type state struct {
	Device    string  `json:"device"`
	Minutes   int     `json:"minutes"`
	Status    string  `json:"status"`
	Error     string  `json:"error,omitempty"`
	Version   int     `json:"version"`
	Seen      float64 `json:"seen"`
	IdleSince float64 `json:"idleSince"`
	Sample    sample  `json:"sample"`
	Sleeping  bool    `json:"sleeping"`
}

func (s *service) stats(d disk) (sample, error) {
	raw, err := os.ReadFile(filepath.Join(s.sys, d.Name, "stat"))
	if err != nil {
		return sample{}, err
	}
	return parseStats(string(raw))
}
func parseStats(raw string) (sample, error) {
	fields := strings.Fields(raw)
	var result sample
	if len(fields) < 11 {
		return result, fmt.Errorf("incomplete disk counters")
	}
	for j, i := range []int{0, 2, 4, 6, 11, 13, 15} {
		if i >= len(fields) {
			continue
		}
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return result, err
		}
		result.Counters[j] = v
	}
	v, err := strconv.ParseUint(fields[8], 10, 64)
	result.InFlight = v
	return result, err
}
func advance(old state, d disk, minutes int, now float64, current sample, busy bool) state {
	next := old
	next.Device = d.Path
	next.Minutes = minutes
	next.Status = "applied"
	next.Error = ""
	// A gap means we cannot prove continuous idle time (boot, stopped timer or slow operation).
	if old.Version != 1 || old.Minutes != minutes || now < old.Seen || now-old.Seen > 90 || old.Sample != current || current.InFlight != 0 || busy || old.Status != "applied" {
		next.IdleSince = now
		next.Sleeping = false
	}
	next.Version = 1
	next.Seen = now
	next.Sample = current
	if busy {
		next.Status = "busy"
	}
	return next
}
func (s *service) smart(d disk) (sleeping, busy bool, err error) {
	raw, code, err := s.run("smartctl", "-n", "standby,3,5", "-d", "ata", "-c", "-j", d.Path)
	var result struct {
		Smart struct {
			Messages []struct {
				Text string `json:"string"`
			} `json:"messages"`
		} `json:"smartctl"`
		ATA struct {
			Test struct {
				Status struct {
					Value *int `json:"value"`
				} `json:"status"`
			} `json:"self_test"`
			Offline struct {
				Status struct {
					Value *int `json:"value"`
				} `json:"status"`
			} `json:"offline_data_collection"`
		} `json:"ata_smart_data"`
	}
	if e := json.Unmarshal(raw, &result); e != nil {
		return false, false, e
	}
	if code == 3 {
		for _, m := range result.Smart.Messages {
			text := strings.ToUpper(m.Text)
			if strings.Contains(text, "STANDBY") || strings.Contains(text, "SLEEP") {
				return true, false, nil
			}
		}
	}
	if code < 0 || code&7 != 0 {
		return false, false, fmt.Errorf("cannot verify SMART state: %v", err)
	}
	if result.ATA.Test.Status.Value == nil {
		return false, false, fmt.Errorf("SMART self-test state unavailable")
	}
	busy = *result.ATA.Test.Status.Value&0xf0 == 0xf0
	if v := result.ATA.Offline.Status.Value; v != nil && *v&0x7f == 3 {
		busy = true
	}
	return false, busy, nil
}
func (s *service) step(d disk, old state, minutes int, now float64) (state, error) {
	current, err := s.stats(d)
	if err != nil {
		return old, err
	}
	busy, err := s.busy(d.Name, map[string]bool{})
	if err != nil {
		return old, err
	}
	next := advance(old, d, minutes, now, current, busy)
	if old.Version != 1 || old.Minutes != minutes {
		// Disable the firmware timer: it must not stop a disk during a SMART test or RAID work.
		if _, _, err = s.run("hdparm", "-S", "0", d.Path); err != nil {
			return next, err
		}
	}
	if minutes == 0 || busy || current.InFlight != 0 || now-next.IdleSince < float64(minutes*60) {
		return next, nil
	}
	sleeping, testing, err := s.smart(d)
	if err != nil {
		return next, err
	}
	if sleeping {
		next.Sleeping = true
		return next, nil
	}
	if testing {
		next.IdleSince = now
		next.Status = "busy"
		next.Sleeping = false
		return next, nil
	}
	if old.Sleeping {
		next.IdleSince = now
		next.Sleeping = false
		return next, nil
	}
	// Recheck identity, protection and I/O after external SMART commands, immediately before standby.
	disks, err := s.inventory()
	if err != nil {
		return next, err
	}
	found := false
	for _, v := range disks {
		if v == d {
			found = true
		}
	}
	if !found {
		return next, fmt.Errorf("disk identity or protection changed")
	}
	after, err := s.stats(d)
	if err != nil {
		return next, err
	}
	busy, err = s.busy(d.Name, map[string]bool{})
	if err != nil {
		return next, err
	}
	if after != current || after.InFlight != 0 || busy {
		next.Sample = after
		next.IdleSince = now
		return next, nil
	}
	if _, _, err = s.run("hdparm", "-y", d.Path); err != nil {
		return next, err
	}
	next.Sleeping = true
	return next, nil
}
