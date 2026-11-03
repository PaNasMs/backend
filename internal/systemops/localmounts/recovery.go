package localmounts

import (
	"panasms.local/backend/internal/systemops/folders"
	"path/filepath"
	"strings"
)

func Recovery(target string) (map[string]any, error) { return defaultService().recovery(target) }
func (s *service) recovery(target string) (map[string]any, error) {
	if !strings.HasPrefix(target, "/dev/") || filepath.Clean(target) != target || filepath.Dir(target) != "/dev" {
		return nil, reject("Select a block device")
	}
	state, revision, err := readJournal(s.root, target, 0)
	if err != nil {
		return nil, err
	}
	mounts, err := s.mounts()
	if err != nil {
		return nil, err
	}
	report := map[string]any{"target": target, "pendingJournal": false, "phase": "No pending journal", "recoveryAction": nil, "mounts": []folders.LiveMount{}}
	if state == nil {
		return report, nil
	}
	report["pendingJournal"] = state.Phase == "pending"
	report["phase"] = state.Phase
	report["action"] = state.Action
	report["steps"] = state.Steps
	report["journalRevision"] = revision
	report["recordedIdentity"] = state.Identity
	if state.Phase == "pending" && (state.StageIntent || state.MountID != 0) {
		report["recoveryAction"] = "mount.detach"
	}
	selected := []folders.LiveMount{}
	for _, mount := range mounts {
		matches := mount.Target == state.Point || mount.Target == state.Stage
		for _, device := range state.Identity.Devices {
			matches = matches || device.DeviceNumber == mount.Device
		}
		if matches {
			selected = append(selected, mount)
		}
	}
	report["mounts"] = selected
	report["message"] = "Inspect the current device and completed steps. Destructive operations are never replayed automatically; a new operation requires a fresh plan and confirmation."
	return report, nil
}
