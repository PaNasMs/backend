package storagebase

import (
	"panasms.local/backend/internal/systemops/storagequery"
	"sort"
	"strings"
)

// These fields acknowledge configuration only; an uncertain disk step is never replayed.
type ConfigRecovery struct {
	ConfigReconciled    bool                         `json:"configReconciled"`
	ConfigResolution    string                       `json:"configResolution"`
	ConfigWitness       string                       `json:"configWitness"`
	ConfigOnlyRemaining bool                         `json:"configOnlyRemaining"`
	ConfigRemovedUUIDs  []string                     `json:"configRemovedUUIDs"`
	ConfigIdentity      storagequery.StorageIdentity `json:"configIdentity"`
}

func (c ConfigRecovery) Acknowledged(current, before, desired string) bool {
	if !c.ConfigReconciled || c.ConfigWitness != Hash(current) {
		return false
	}
	switch c.ConfigResolution {
	case "before":
		return !c.ConfigOnlyRemaining && Hash(current) == before
	case "desired":
		return current == desired
	}
	return false
}

func RemovedFstabUUIDs(before, after string) []string {
	rows := func(data string) map[string]bool {
		out := map[string]bool{}
		for _, line := range strings.Split(data, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 && strings.HasPrefix(fields[0], "UUID=") {
				out[strings.TrimPrefix(fields[0], "UUID=")] = true
			}
		}
		return out
	}
	old, current := rows(before), rows(after)
	result := []string{}
	for uuid := range old {
		if !current[uuid] {
			result = append(result, uuid)
		}
	}
	sort.Strings(result)
	return result
}
