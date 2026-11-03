package modulelifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"panasms.local/backend/internal/systemops"
)

func TestGeneratedUnitPreservesIdentityAndShellIsolation(t *testing.T) {
	for _, shell := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "terminal"}[shell], func(t *testing.T) {
			s := fixtureStore(t)
			manifest := Manifest{"id": "example", "service": "bin/server", "userShell": shell}
			if err := writeUnit("/var/lib/panasms-modules", s.root, manifest, s.owner); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.root, unit("example"))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, required := range []string{"User=root\nGroup=panasms", "ExecStart=/var/lib/panasms-modules/example/bin/server", "KillMode=control-group", "RuntimeDirectoryPreserve=yes", "PANASMS_MAINTENANCE_LOCK=/run/lock/panasms-maintenance.lock", "UMask=0077", "PrivateTmp=yes"} {
				if !strings.Contains(string(raw), required) {
					t.Fatal("lost service contract", required)
				}
			}
			want := "NoNewPrivileges=yes"
			if shell {
				want = "NoNewPrivileges=no"
			}
			if !strings.Contains(string(raw), want) {
				t.Fatal(string(raw))
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0644 {
				t.Fatal(info.Mode())
			}
			if err = os.Rename(path, path+".saved"); err != nil {
				t.Fatal(err)
			}
			if err = os.Symlink(path+".saved", path); err != nil {
				t.Fatal(err)
			}
			if err = writeUnit("/var/lib/panasms-modules", s.root, manifest, s.owner); err == nil {
				t.Fatal("foreign unit link overwritten")
			}
			if _, err = os.Readlink(path); err != nil {
				t.Fatal("foreign unit lost", err)
			}
		})
	}
	for _, root := range []string{"relative", "/tmp/escape\nExecStart=other", "/tmp/percent%", "/tmp/space root"} {
		if _, err := unitContent(root, Manifest{"id": "example", "service": "bin/server"}); err == nil {
			t.Fatal("unsafe unit path accepted", root)
		}
	}
}

func TestIdleBarrierRejectsUnknownAndActiveWork(t *testing.T) {
	inactive := func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
		return []byte("inactive"), nil
	}
	manifest := Manifest{"id": "example", "enabled": true, "service": "bin/server"}
	for _, result := range []map[string]any{
		{}, {"active": json.Number("0")}, {"maintenanceVersion": json.Number("1")},
		{"maintenanceVersion": json.Number("1"), "active": json.Number("1")},
		{"maintenanceVersion": json.Number("1"), "active": json.Number("-1")},
		{"maintenanceVersion": json.Number("1"), "active": "0"},
	} {
		if err := requireIdle(context.Background(), manifest, func(context.Context, string) (map[string]any, error) { return result, nil }, inactive); err == nil {
			t.Fatal("uncertain active work accepted", result)
		}
	}
	if err := requireIdle(context.Background(), manifest, func(context.Context, string) (map[string]any, error) {
		return map[string]any{"maintenanceVersion": json.Number("1"), "active": json.Number("0")}, nil
	}, inactive); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []error{os.ErrNotExist, syscall.ECONNREFUSED} {
		if err := requireIdle(context.Background(), manifest, func(context.Context, string) (map[string]any, error) { return nil, missing }, inactive); err != nil {
			t.Fatal(err)
		}
	}
	if err := requireIdle(context.Background(), manifest, func(context.Context, string) (map[string]any, error) { return nil, os.ErrPermission }, inactive); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	manifest["enabled"] = false
	if err := requireIdle(context.Background(), manifest, func(context.Context, string) (map[string]any, error) {
		t.Fatal("disabled service queried")
		return nil, nil
	}, inactive); err != nil {
		t.Fatal(err)
	}
}

func TestStartModuleUsesActualCommandAndHealthOutcome(t *testing.T) {
	manifest := Manifest{"id": "example", "service": "bin/server"}
	calls := [][]string{}
	run := func(_ context.Context, argv []string, options systemops.CommandOptions) ([]byte, error) {
		calls = append(calls, argv)
		if !options.Operation {
			t.Fatal("service mutation marked read-only")
		}
		return nil, nil
	}
	checks := 0
	if err := startModule(context.Background(), manifest, run, func(context.Context, string) (map[string]any, error) { checks++; return map[string]any{}, nil }, nil); err != nil {
		t.Fatal(err)
	}
	if checks != 1 || !reflect.DeepEqual(calls, [][]string{{"systemctl", "enable", "--now", "panasms-module-example.service"}}) {
		t.Fatal(calls, checks)
	}
	failed := errors.New("service failed")
	if err := startModule(context.Background(), manifest, func(context.Context, []string, systemops.CommandOptions) ([]byte, error) { return nil, failed }, func(context.Context, string) (map[string]any, error) {
		t.Fatal("health queried after failed start")
		return nil, nil
	}, nil); !errors.Is(err, failed) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := startModule(ctx, manifest, run, func(context.Context, string) (map[string]any, error) { return nil, failed }, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestUnavailableHealthNeverBlessesActiveOrTransitioningService(t *testing.T) {
	manifest := Manifest{"id": "example", "enabled": true, "service": "bin/server"}
	for _, state := range []string{"active", "activating", "deactivating", "unexpected"} {
		if err := requireIdle(context.Background(), manifest, func(context.Context, string) (map[string]any, error) { return nil, syscall.ECONNREFUSED }, func(_ context.Context, argv []string, options systemops.CommandOptions) ([]byte, error) {
			if options.Operation || !reflect.DeepEqual(argv, []string{"systemctl", "is-active", unit("example")}) {
				t.Fatal(argv, options)
			}
			return []byte(state), nil
		}); err == nil {
			t.Fatal("unavailable active health accepted", state)
		}
	}
}
