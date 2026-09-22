package api

import (
	"fmt"
	"os"
	"panasms.local/backend/internal/external"
	"panasms.local/backend/internal/modules"
	"path/filepath"
	"syscall"
)

type grantPolicy struct {
	Scope    string
	Provider string
}

// Consumers opt into reviewed capabilities; modules cannot supply OAuth scopes or endpoints.
var grantPolicies = map[string]map[string]grantPolicy{
	"cloud-sync": {
		"google-drive":          {Scope: external.DriveScope, Provider: "google"},
		"google-drive-readonly": {Scope: external.DriveReadScope, Provider: "google"},
	},
}

func grantInstallation(consumer, capability string) (grantPolicy, string, bool) {
	policy, ok := grantPolicies[consumer][capability]
	if !ok {
		return policy, "", false
	}
	m, ok := modules.Read()[consumer]
	if !ok || !m.Enabled {
		return policy, "", false
	}
	if m.Installation != "" {
		return policy, m.Installation, true
	}
	info, err := os.Stat(filepath.Join(modules.Root, consumer))
	if err != nil {
		return policy, "", false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return policy, "", false
	}
	return policy, fmt.Sprintf("legacy:%d:%d:%d:%d", st.Dev, st.Ino, st.Ctim.Sec, st.Ctim.Nsec), true
}
