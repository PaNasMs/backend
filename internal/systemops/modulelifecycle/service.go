package modulelifecycle

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/folders"
)

func (s *lifecycle) refreshCore() error {
	if s.coreFile == "" {
		return nil
	}
	dir, err := trustedDirectory(filepath.Dir(s.coreFile), s.owner)
	if err != nil {
		return err
	}
	defer dir.Close()
	raw, err := readOwnedAt(dir, filepath.Base(s.coreFile), s.owner, 100)
	if err != nil {
		return err
	}
	core := strings.TrimSpace(string(raw))
	if _, err = parseVersion(core); err != nil {
		return err
	}
	s.core = core
	return nil
}

func installedLifecycle() (lifecycle, error) {
	s := lifecycle{store: store{root: "/var/lib/panasms-modules", owner: 0}, coreFile: "/usr/lib/panasms/VERSION", architecture: runtime.GOARCH,
		units: "/etc/systemd/system", uploads: "/var/lib/panasms-agent/module-uploads", keys: "/etc/panasms/module-keys", maintenance: "/run/lock/panasms-maintenance.lock",
		run: systemops.Command, compare: compareDebian, health: health, mounts: func() ([]string, error) {
			rows, err := folders.ReadMounts()
			if err != nil {
				return nil, err
			}
			paths := make([]string, 0, len(rows))
			for _, row := range rows {
				paths = append(paths, row.Target)
			}
			return paths, nil
		}}
	if err := s.refreshCore(); err != nil {
		return lifecycle{}, err
	}
	return s, nil
}

func Query(member bool) (json.RawMessage, error) {
	s, err := installedLifecycle()
	if err != nil {
		return nil, err
	}
	return queryRegistry(s.store, s.core, member)
}

func Plan(ctx context.Context, action string, params map[string]any, user string) (json.RawMessage, error) {
	s, err := installedLifecycle()
	if err != nil {
		return nil, err
	}
	return s.plan(ctx, action, params, user)
}

func Execute(ctx context.Context, action string, params map[string]any, user, expected string, reporter *systemops.Reporter, authorize func() error) (json.RawMessage, error) {
	s, err := installedLifecycle()
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	return s.execute(ctx, action, params, user, expected, reporter, authorize)
}

func Inspect() (json.RawMessage, error) {
	s, err := installedLifecycle()
	if err != nil {
		return nil, err
	}
	state, err := s.loadTransaction()
	if err != nil {
		return nil, err
	}
	result := map[string]any{"pending": state != nil}
	if state != nil {
		result["modules"] = state.Affected
		result["committed"] = state.Committed
	}
	return json.Marshal(result)
}
