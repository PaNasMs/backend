package networkmounts

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (s *service) busyDescription(raw string) string {
	labels := []string{}
	for _, pid := range strings.Fields(raw) {
		number, err := strconv.Atoi(pid)
		if err != nil || number < 1 {
			continue
		}
		name := ""
		comm, _ := os.ReadFile(filepath.Join(s.proc, pid, "comm"))
		if len(comm) < 256 {
			name = strings.TrimSpace(string(comm))
		}
		group, _ := os.ReadFile(filepath.Join(s.proc, pid, "cgroup"))
		if len(group) < 65536 {
			for _, part := range strings.FieldsFunc(string(group), func(r rune) bool { return r == '/' || r == '\n' }) {
				if strings.HasSuffix(part, ".service") {
					name = part
				}
			}
		}
		label := pid
		if name != "" {
			label += " (" + name + ")"
		}
		labels = append(labels, label)
	}
	if len(labels) == 0 {
		return strings.TrimSpace(raw)
	}
	return strings.Join(labels, ", ")
}
func Recovery(point string) (map[string]any, error) { return defaultService().recovery(point) }
func (s *service) recovery(point string) (map[string]any, error) {
	if err := s.path(point); err != nil {
		return nil, err
	}
	state, err := s.load(point)
	if err != nil {
		return nil, err
	}
	rows, err := s.mounts()
	if err != nil {
		return nil, err
	}
	result := map[string]any{"point": point, "mounted": false, "phase": "No pending journal", "pendingJournal": state != nil, "recoveryAction": nil}
	if state != nil {
		result["phase"] = state.Phase
		result["source"] = state.Source
		switch state.FSType {
		case "cifs":
			result["recoveryAction"] = "smb.unmount"
		case "nfs":
			result["recoveryAction"] = "nfs.unmount"
		}
	}
	for _, row := range rows {
		if row.Target == point {
			result["mounted"] = true
			result["source"] = row.Source
			result["filesystem"] = row.FSType
		}
	}
	return result, nil
}
