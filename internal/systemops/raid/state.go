package raid

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/accounts"
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
)

type member struct {
	Path  string   `json:"path"`
	Slot  string   `json:"slot"`
	State []string `json:"state"`
}

type arrayState struct {
	UUID, Level, Metadata, Sync, Array, Layout string
	Count, Degraded                            int
	ComponentKiB, Chunk                        uint64
	Reshaping                                  bool
	Members                                    []member
}

type runner func(context.Context, []string, systemops.CommandOptions) ([]byte, error)

type service struct {
	sys, reshapeRoot, config string
	owner                    int
	load                     func(context.Context) (*storagequery.Preflight, error)
	identity                 func(*storagequery.Preflight, string) (storagequery.StorageIdentity, error)
	resolve                  func(string) (string, error)
	mounts                   func() ([]folders.LiveMount, error)
	shares                   func() ([]accounts.StorageShare, error)
	readFstab                func() (string, error)
	run                      runner
}

func defaultService() *service {
	return &service{sys: "/sys/class/block", reshapeRoot: "/var/lib/panasms-agent/raid-reshape", config: "/etc/mdadm/mdadm.conf",
		load: storagequery.LoadPreflight, identity: func(p *storagequery.Preflight, target string) (storagequery.StorageIdentity, error) {
			return p.Identity(target)
		},
		resolve: filepath.EvalSymlinks, mounts: folders.ReadMounts, shares: accounts.StorageShares, readFstab: storagebase.ReadFstab, run: systemops.Command}
}

func reject(message string) error              { return &systemops.Rejected{Message: message} }
func text(p map[string]any, key string) string { value, _ := p[key].(string); return value }
func IsAction(action string) bool {
	return slices.Contains([]string{"raid.create", "raid.delete", "raid.add", "raid.grow", "raid.replace", "raid.check", "raid.check-stop", "raid.pause", "raid.resume", "raid.convert"}, action)
}

var arrayName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,30}$`)
var uuidPattern = regexp.MustCompile(`^(?i:(?:[0-9a-f]{8}:){3}[0-9a-f]{8}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
var kernelName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func uintValue(value any) (uint64, error) {
	var source string
	switch v := value.(type) {
	case json.Number:
		source = string(v)
	case string:
		source = v
	case uint64:
		return v, nil
	case int:
		if v >= 0 {
			return uint64(v), nil
		}
	case float64:
		if v >= 0 && v < 1<<53 && v == float64(uint64(v)) {
			return uint64(v), nil
		}
	}
	v, err := strconv.ParseUint(source, 10, 64)
	if err != nil {
		return 0, reject("Could not verify array geometry")
	}
	return v, nil
}

func (s *service) readArray(name string) (*arrayState, error) {
	if !kernelName.MatchString(name) {
		return nil, reject("The device is not an MD RAID array")
	}
	root := filepath.Join(s.sys, name, "md")
	read := func(key string) (string, error) {
		data, err := os.ReadFile(filepath.Join(root, key))
		return strings.TrimSpace(string(data)), err
	}
	values := map[string]string{}
	for _, key := range []string{"uuid", "level", "metadata_version", "raid_disks", "degraded", "sync_action", "reshape_position", "array_state", "component_size", "chunk_size", "layout"} {
		v, err := read(key)
		if os.IsNotExist(err) && values["level"] == "raid0" {
			switch key {
			case "degraded":
				v, err = "0", nil
			case "sync_action":
				v, err = "idle", nil
			}
		}
		if err != nil {
			return nil, fmt.Errorf("Could not inspect RAID state (%s): %w", key, err)
		}
		values[key] = v
	}
	count, err := strconv.Atoi(values["raid_disks"])
	if err != nil || count < 2 || count > 4096 {
		return nil, reject("Could not verify array membership")
	}
	degraded, err := strconv.Atoi(values["degraded"])
	if err != nil || degraded < 0 || degraded > count {
		return nil, reject("Could not verify array membership")
	}
	component, err := uintValue(values["component_size"])
	if err != nil {
		return nil, err
	}
	chunk, err := uintValue(values["chunk_size"])
	if err != nil {
		return nil, err
	}
	position := values["reshape_position"]
	if position != "none" {
		if _, err = strconv.ParseUint(position, 10, 64); err != nil {
			return nil, reject("Could not verify array reshape state")
		}
	}
	if !uuidPattern.MatchString(values["uuid"]) {
		return nil, reject("Invalid RAID UUID")
	}
	state := &arrayState{UUID: values["uuid"], Level: values["level"], Metadata: values["metadata_version"], Count: count, Degraded: degraded,
		Sync: values["sync_action"], Array: values["array_state"], Layout: values["layout"], ComponentKiB: component, Chunk: chunk, Reshaping: position != "none", Members: []member{}}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "dev-") {
			continue
		}
		name := strings.TrimPrefix(entry.Name(), "dev-")
		if !kernelName.MatchString(name) {
			return nil, reject("Could not verify array membership")
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name(), "state"))
		if err != nil {
			return nil, err
		}
		slot, err := os.ReadFile(filepath.Join(root, entry.Name(), "slot"))
		if err != nil {
			return nil, err
		}
		block, err := filepath.EvalSymlinks(filepath.Join(root, entry.Name(), "block"))
		if err != nil || filepath.Base(block) != name {
			return nil, reject("Could not confirm the RAID member device")
		}
		states := strings.Split(strings.TrimSpace(string(data)), ",")
		sort.Strings(states)
		state.Members = append(state.Members, member{Path: "/dev/" + name, Slot: strings.TrimSpace(string(slot)), State: states})
	}
	sort.Slice(state.Members, func(i, j int) bool { return state.Members[i].Path < state.Members[j].Path })
	if len(state.Members) == 0 {
		return nil, reject("Could not verify array membership")
	}
	return state, nil
}

func synchronized(state *arrayState) bool {
	if state.Degraded != 0 || len(state.Members) != state.Count {
		return false
	}
	slots := map[int]bool{}
	for _, m := range state.Members {
		slot, err := strconv.Atoi(m.Slot)
		if err != nil || slot < 0 || slot >= state.Count || slots[slot] || !slices.Contains(m.State, "in_sync") || badMember(m) {
			return false
		}
		slots[slot] = true
	}
	return len(slots) == state.Count
}

func badMember(m member) bool {
	return slices.Contains(m.State, "faulty") || slices.Contains(m.State, "blocked") || slices.Contains(m.State, "write_error")
}

func within(path, point string) bool {
	return path == point || strings.HasPrefix(path, strings.TrimRight(point, "/")+"/")
}
