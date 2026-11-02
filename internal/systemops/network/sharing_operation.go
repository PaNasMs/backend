package network

import (
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/godbus/dbus/v5"
)

func storeNMGroups(groups []nmGroup) error {
	if groups == nil {
		groups = []nmGroup{}
	}
	return writeNetworkJSON(filepath.Join(sharingRoot, "groups.json"), groups)
}
func (a *adapter) sharingExecute(action, user string, p map[string]any) (any, error) {
	if _, e := a.sharingPlan(action, user, p); e != nil {
		return nil, e
	}
	groups, e := loadNMGroups()
	if e != nil {
		return nil, e
	}
	id, _ := p["id"].(string)
	old := nmGroupByID(groups, id)
	effective, e := sharingEffective(action, p, old)
	if e != nil {
		return nil, e
	}
	var conf nmGroup
	if action == "network.share.save" || action == "network.share.wifi" {
		conf, _, e = a.reviewNMSharing(effective, old)
		if e != nil {
			return nil, e
		}
	} else {
		conf = *old
	}
	names := nmGroupNames(conf)
	if old != nil {
		for _, name := range nmGroupNames(*old) {
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	paths := []dbus.ObjectPath{}
	for _, name := range names {
		path, _, e := a.device(name)
		if e != nil {
			if missingDevice(e) && slices.Contains([]string{"network.share.stop", "network.share.delete", "network.share.remove-port"}, action) {
				continue
			}
			return nil, fmt.Errorf("A network adapter is disconnected")
		}
		paths = append(paths, path)
	}
	if old != nil && old.Enabled {
		path, _, e := a.device(old.Bridge)
		if e == nil {
			paths = append(paths, path)
		} else if !missingDevice(e) {
			return nil, e
		}
	}
	transactionID, e := randomID()
	if e != nil {
		return nil, e
	}
	boot, e := bootID()
	if e != nil {
		return nil, e
	}
	previous, e := a.originalNM(names)
	if e != nil {
		return nil, e
	}
	before, e := a.radioSnapshot()
	if e != nil {
		return nil, e
	}
	s := &nmChange{state: state{ID: transactionID, Kind: action, Interface: conf.Source, User: user, Status: "applying", Deadline: float64(time.Now().Unix()) + 150, Addresses: []string{}}, HashVersion: 1, Boot: boot, Before: groups, Previous: previous, NewUUIDs: []string{}, NewProfiles: map[string]string{}, AdaptersBefore: &before}
	if len(paths) > 0 {
		if e = a.call(nmPath, nm+".CheckpointCreate", paths, uint32(180), uint32(0)).Store(&s.Checkpoint); e != nil {
			return nil, e
		}
	}
	if e = s.remember(); e != nil {
		if s.Checkpoint != "" {
			_ = a.rollback(s.Checkpoint)
		}
		return nil, e
	}
	immediate := false
	apply := func() error {
		if e := s.arm(150); e != nil {
			return e
		}
		var g nmGroup
		if action == "network.share.save" || action == "network.share.wifi" {
			g, e = a.buildNMGroup(conf, effective, old, s)
			if e != nil {
				return e
			}
			if action == "network.share.wifi" {
				g.Enabled = old.Enabled
			}
		} else if action == "network.share.remove-port" {
			name, _ := p["interface"].(string)
			g, e = withoutNMPort(old, name)
			if e != nil {
				return e
			}
		} else {
			g = *old
			g.Enabled = action == "network.share.start"
		}
		s.After = []nmGroup{}
		for _, prior := range groups {
			if old == nil || prior.ID != old.ID {
				s.After = append(s.After, prior)
			}
		}
		if action != "network.share.delete" && (action != "network.share.remove-port" || len(g.Outputs) > 0) {
			s.After = append(s.After, g)
		}
		s.Working = &g
		if e = s.remember(); e != nil {
			return e
		}
		removing := action == "network.share.remove-port"
		if removing {
			name, _ := p["interface"].(string)
			if e = a.detachNMPort(*old, name); e != nil {
				return e
			}
			if len(g.Outputs) == 0 {
				if old.Enabled {
					if e = a.deactivateNMGroup(*old); e != nil {
						return e
					}
				}
				g.Enabled = false
			}
		} else if old != nil && old.Enabled {
			if e = a.deactivateNMGroup(*old); e != nil {
				return e
			}
		}
		if g.Enabled && !removing {
			for _, name := range nmGroupNames(g) {
				_, props, e := a.device(name)
				if e != nil {
					return e
				}
				if num(props["DeviceType"]) == 2 {
					if e = a.enableRadio(name); e != nil {
						return e
					}
				}
			}
			if e = a.activateNMGroup(g, false); e != nil {
				return e
			}
			deadline := time.Unix(int64(s.Deadline)-30, 0)
			if limit := time.Now().Add(90 * time.Second); limit.Before(deadline) {
				deadline = limit
			}
			if e = a.waitNMGroup(g, deadline); e != nil {
				return e
			}
		}
		profiles, e := a.profiles()
		if e != nil {
			return e
		}
		s.ProfileHashes = map[string]string{}
		wanted := map[string]bool{}
		for _, id := range g.Profiles {
			wanted[id] = true
		}
		for id, p := range profiles {
			if wanted[id] {
				s.ProfileHashes[id] = signature(p.Settings)
			}
		}
		s.Status = "pending"
		if e = s.remember(); e != nil {
			return e
		}
		if e = storeNMGroups(s.After); e != nil {
			return e
		}
		immediate = removing && len(g.Outputs) > 0
		if immediate {
			return a.confirmNMSharing(s)
		}
		return nil
	}
	if e = apply(); e != nil {
		// A persisted confirmation is a commit boundary; never roll it back after cleanup errors.
		if s.Status == "confirmed" {
			return nil, fmt.Errorf("Sharing changes were confirmed; cleanup requires recovery")
		}
		if rollback := a.rollbackNMSharing(s); rollback != nil {
			return nil, fmt.Errorf("Sharing operation interrupted; recovery is required")
		}
		return nil, fmt.Errorf("Sharing could not start; previous settings were restored")
	}
	if immediate {
		return map[string]any{"message": "Sharing recipient removed"}, nil
	}
	return map[string]any{"message": "Network changes await confirmation", "change": public(&s.state)}, nil
}
func (a *adapter) rollbackNMSharing(s *nmChange) error {
	if s.AdaptersBefore != nil {
		if e := a.restoreRadios(*s.AdaptersBefore); e != nil {
			return e
		}
	}
	checkpoints, e := a.checkpoints()
	if e != nil {
		return e
	}
	if slices.Contains(checkpoints, s.Checkpoint) {
		if e = a.rollback(s.Checkpoint); e != nil {
			return e
		}
	}
	if e = a.deleteProfiles(s.NewUUIDs); e != nil {
		return e
	}
	if s.Working != nil {
		if e = cleanupNMRouting(*s.Working); e != nil {
			return e
		}
	}
	if e = a.restoreNM(s.Previous); e != nil {
		return e
	}
	if e = storeNMGroups(s.Before); e != nil {
		return e
	}
	for _, g := range s.Before {
		if g.Enabled {
			if e = a.activateNMGroup(g, true); e != nil {
				return e
			}
		}
	}
	s.Status = "rolled-back"
	s.Error = ""
	if e = s.remember(); e != nil {
		return e
	}
	return s.disarm()
}
func (a *adapter) confirmNMSharing(s *nmChange) error {
	checkpoints, e := a.checkpoints()
	if e != nil {
		return e
	}
	if s.Checkpoint != "" {
		if !slices.Contains(checkpoints, s.Checkpoint) {
			return fmt.Errorf("This network change has expired or is no longer pending")
		}
		if e = a.call(nmPath, nm+".CheckpointAdjustRollbackTimeout", s.Checkpoint, uint32(60)).Err; e != nil {
			return e
		}
	}
	saved, e := a.profiles()
	if e != nil {
		return e
	}
	for id, hash := range s.ProfileHashes {
		p, ok := saved[id]
		if !ok || !s.matchesProfile(p.Settings, hash) {
			return fmt.Errorf("Sharing configuration changed externally; roll back and review it again")
		}
	}
	for _, id := range s.NewUUIDs {
		p, ok := saved[id]
		if !ok {
			return fmt.Errorf("Sharing configuration changed externally; roll back and review it again")
		}
		if e = a.call(p.Path, nm+".Settings.Connection.Save").Err; e != nil {
			return e
		}
	}
	if s.Checkpoint != "" {
		if e = a.call(nmPath, nm+".CheckpointDestroy", s.Checkpoint).Err; e != nil {
			return e
		}
	}
	s.Status = "confirmed"
	if e = s.remember(); e != nil {
		return e
	}
	if e = s.disarm(); e != nil {
		return e
	}
	return a.cleanupNMConfirmed(s)
}
func (a *adapter) cleanupNMConfirmed(s *nmChange) error {
	keep := map[string]bool{}
	for _, g := range s.After {
		for _, id := range g.Profiles {
			keep[id] = true
		}
	}
	remove := []string{}
	for _, g := range s.Before {
		for _, id := range g.Profiles {
			if !keep[id] {
				remove = append(remove, id)
			}
		}
	}
	return a.deleteProfiles(remove)
}
