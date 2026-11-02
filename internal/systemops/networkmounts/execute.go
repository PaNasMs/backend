package networkmounts

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"panasms.local/backend/internal/systemops"
	"path/filepath"
	"strings"
)

func Execute(ctx context.Context, action string, p map[string]any, name, expected string, r *systemops.Reporter) (json.RawMessage, error) {
	return defaultService().execute(ctx, action, p, name, expected, r)
}
func (s *service) execute(ctx context.Context, action string, p map[string]any, name, expected string, r *systemops.Reporter) (json.RawMessage, error) {
	lock, err := s.lock()
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer lock.Close()
	plan, err := s.prepare(ctx, action, p, name)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	var public struct{ Fingerprint string }
	if err = json.Unmarshal(plan.raw, &public); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if expected == "" || public.Fingerprint != expected {
		return nil, systemops.BeforeMutation(reject("State has changed. Review a new operation plan."))
	}
	if strings.HasSuffix(action, ".unmount") {
		return s.executeUnmount(ctx, action, plan, r)
	}
	state := &transaction{Schema: 1, Point: plan.point, Source: param(p, "target"), FSType: "nfs", Phase: "preparing", BeforeHash: hashText(plan.conf)}
	if action == "smb.mount" {
		state.FSType = "cifs"
	}
	if err = s.save(state); err != nil {
		return nil, err
	}
	target, err := createPinnedTarget(plan.point, plan.witness)
	if err != nil {
		return nil, s.abortMount(ctx, state, err, r)
	}
	defer target.Close()
	if err = emptyTarget(target); err != nil {
		return nil, s.abortMount(ctx, state, err, r)
	}
	stage := filepath.Join(s.root, Key(plan.point)+".stage")
	if err = os.Mkdir(stage, 0700); err != nil {
		return nil, err
	}
	state.Stage = true
	if err = s.save(state); err != nil {
		return nil, s.abortMount(ctx, state, err, r)
	}
	opts := "rw,nosuid,nodev,_netdev"
	if p["readOnly"] == true {
		opts = "ro,nosuid,nodev,_netdev"
	}
	if action == "smb.mount" {
		if err = s.createCredential(state, p); err != nil {
			return nil, s.abortMount(ctx, state, err, r)
		}
		opts += ",credentials=" + filepath.Join(s.credentials, Key(plan.point)) + ",uid=" + plan.identity[0] + ",gid=" + plan.identity[1] + ",file_mode=0600,dir_mode=0700,vers=3.0"
	}
	_, err = s.run(ctx, []string{"mount", "-t", state.FSType, "-o", opts, "--", state.Source, stage}, systemops.CommandOptions{Operation: true, Reporter: r})
	if err != nil {
		message := "Could not mount network share. Check its address, server availability and read/write permissions"
		if state.FSType == "cifs" {
			message += ", and the SMB username and password."
		} else {
			message += " for the PaNasMs IP address in NFS rules."
		}
		return nil, s.abortMount(ctx, state, reject(message), r)
	}
	state.Phase = "staged"
	if err = s.save(state); err != nil {
		return nil, s.abortMount(ctx, state, err, r)
	}
	if err = sameDirectory(target, plan.point); err != nil {
		return nil, s.abortMount(ctx, state, err, r)
	}
	if err = emptyTarget(target); err != nil {
		return nil, s.abortMount(ctx, state, err, r)
	}
	_, err = s.attach(stage, target, func(id uint64) error { state.MountID = id; state.Phase = "attaching"; return s.save(state) })
	if err != nil {
		return nil, s.abortMount(ctx, state, err, r)
	}
	currentMounts, err := s.mounts()
	if err != nil {
		return nil, s.abortMount(ctx, state, err, r)
	}
	attached := false
	for _, m := range currentMounts {
		attached = attached || (m.ID == state.MountID && m.Target == state.Point && m.Source == state.Source && compatibleFS(m.FSType, state.FSType))
	}
	if !attached {
		return nil, s.abortMount(ctx, state, reject("The mount point changed; review a new operation plan"), r)
	}
	state.Phase = "mounted"
	if err = s.save(state); err != nil {
		return nil, s.abortMount(ctx, state, err, r)
	}
	if p["automount"] == true {
		opts += ",nofail,x-systemd.mount-timeout=30s"
		prefix := plan.conf
		if prefix != "" && !strings.HasSuffix(prefix, "\n") {
			prefix += "\n"
		}
		after := prefix + fmt.Sprintf("%s %s %s %s 0 0 %s\n", state.Source, plan.point, state.FSType, opts, marker(plan.point))
		state.AfterHash = hashText(after)
		if err = s.save(state); err != nil {
			return nil, s.abortMount(ctx, state, err, r)
		}
		current, err := os.ReadFile(s.fstab)
		if err != nil {
			return nil, s.abortMount(ctx, state, err, r)
		}
		if string(current) != plan.conf {
			return nil, s.abortMount(ctx, state, reject("Network mount configuration changed; review recovery before continuing"), r)
		}
		if err = s.write(s.fstab, after, 0644); err != nil {
			return nil, s.abortMount(ctx, state, err, r)
		}
		if _, err = s.run(ctx, []string{"systemctl", "daemon-reload"}, systemops.CommandOptions{Operation: true, Reporter: r}); err != nil {
			return nil, s.abortMount(ctx, state, err, r)
		}
	}
	if err = os.Remove(stage); err != nil {
		return nil, err
	}
	state.Stage = false
	if err = s.save(state); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"message": "Network share mounted", "point": plan.point})
}
func compatibleFS(actual, expected string) bool {
	return actual == expected || expected == "nfs" && actual == "nfs4"
}
func (s *service) abortMount(ctx context.Context, state *transaction, cause error, r *systemops.Reporter) error {
	raw, err := os.ReadFile(s.fstab)
	if err != nil {
		return err
	}
	current := hashText(string(raw))
	if current != state.BeforeHash && current != state.AfterHash {
		return reject("Network mount configuration changed; review recovery before continuing")
	}
	if err := s.cleanupMount(ctx, state, current, r); err != nil {
		return reject("Network mount recovery is required; preserve its configuration and credentials")
	}
	return cause
}
func (s *service) cleanupMount(ctx context.Context, state *transaction, expectedConf string, r *systemops.Reporter) error {
	mounts, err := s.mounts()
	if err != nil {
		return err
	}
	stage := filepath.Join(s.root, Key(state.Point)+".stage")
	for _, m := range mounts {
		ownedStage := state.Stage && m.Target == stage && m.Source == state.Source && compatibleFS(m.FSType, state.FSType)
		ownedAttached := state.MountID != 0 && m.ID == state.MountID
		if m.Target == stage && !ownedStage {
			return reject("Network mount recovery state is invalid")
		}
		if ownedAttached && (m.Target != state.Point || m.Source != state.Source || !compatibleFS(m.FSType, state.FSType)) {
			return reject("The mount changed; review a new operation plan")
		}
		if ownedStage || ownedAttached {
			if err = s.unmount(m.Target, m); err != nil {
				return err
			}
		}
	}
	if err = s.removeConfigured(ctx, state, expectedConf, r); err != nil {
		return err
	}
	if err = s.removeCredential(state); err != nil {
		return err
	}
	if state.Stage {
		if err = os.Remove(stage); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return s.removeState(state.Point)
}
func (s *service) removeConfigured(ctx context.Context, state *transaction, expectedConf string, r *systemops.Reporter) error {
	point := state.Point
	raw, err := os.ReadFile(s.fstab)
	if err != nil {
		return err
	}
	if hashText(string(raw)) != expectedConf {
		return reject("Network mount configuration changed; review recovery before continuing")
	}
	row, err := ownedEntry(string(raw), point)
	if err != nil {
		return err
	}
	if row == nil {
		return nil
	}
	if row[0] != state.Source || !compatibleFS(row[2], state.FSType) {
		return reject("Network mount configuration changed; review recovery before continuing")
	}
	lines := []string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if !strings.HasSuffix(strings.TrimSpace(line), marker(point)) {
			lines = append(lines, line)
		}
	}
	after := strings.Join(lines, "\n") + "\n"
	trimmed := strings.TrimSuffix(after, "\n")
	if hashText(trimmed) == state.BeforeHash {
		after = trimmed
	}
	if err = s.write(s.fstab, after, 0644); err != nil {
		return err
	}
	_, err = s.run(ctx, []string{"systemctl", "daemon-reload"}, systemops.CommandOptions{Operation: true, Reporter: r})
	return err
}
func (s *service) executeUnmount(ctx context.Context, action string, plan *preparedPlan, r *systemops.Reporter) (json.RawMessage, error) {
	state := plan.record
	if state == nil {
		state = &transaction{Schema: 1, Point: plan.point, FSType: "nfs", Phase: "mounted", BeforeHash: hashText(plan.conf)}
		if action == "smb.unmount" {
			state.FSType = "cifs"
		}
		for _, m := range plan.mounts {
			if m.Target == plan.point {
				state.Source = m.Source
				state.MountID = m.ID
			}
		}
		if state.Source == "" {
			row, _ := ownedEntry(plan.conf, plan.point)
			state.Source = row[0]
		}
	}
	if err := s.adoptLegacyCredential(state); err != nil {
		return nil, err
	}
	boot, err := currentBootID()
	if err != nil {
		return nil, err
	}
	if state.BootID != "" && state.BootID != boot {
		state.MountID = 0
	}
	state.BootID = boot
	for _, m := range plan.mounts {
		if m.Target == plan.point {
			state.MountID = m.ID
		}
	}
	if err := s.save(state); err != nil {
		return nil, err
	}
	for _, m := range plan.mounts {
		if m.Target == plan.point {
			if err := s.unmount(plan.point, m); err != nil {
				return nil, err
			}
		}
	}
	state.Phase = "unmounted"
	if err := s.save(state); err != nil {
		return nil, err
	}
	if err := s.cleanupMount(ctx, state, hashText(plan.conf), r); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"message": "Network share unmounted"})
}
func emptyTarget(file *os.File) error {
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}
	rows, err := file.ReadDir(1)
	if err != nil && err != io.EOF {
		return err
	}
	if len(rows) > 0 {
		return reject("The mount point must be an empty directory")
	}
	return nil
}
