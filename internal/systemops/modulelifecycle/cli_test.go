package modulelifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

func TestMaintenanceAncestorRequiresActualAncestorExclusiveInode(t *testing.T) {
	if path := os.Getenv("GO14_ANCESTOR_LOCK"); path != "" {
		lease, err := openMaintenance(path, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		defer lease.file.Close()
		found, err := maintenanceAncestor(lease)
		if err != nil || found != (os.Getenv("GO14_EXPECT_ANCESTOR") == "yes") {
			t.Fatal(found, err)
		}
		return
	}
	s := executionFixture(t)
	file, err := os.Open(s.maintenance)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, mode := range []string{"none", "shared", "exclusive", "other-inode"} {
		t.Run(mode, func(t *testing.T) {
			if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
				t.Fatal(err)
			}
			expected, path := "no", s.maintenance
			if mode == "shared" {
				if err := unix.Flock(int(file.Fd()), unix.LOCK_SH); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "exclusive" || mode == "other-inode" {
				if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
					t.Fatal(err)
				}
				expected = "yes"
				if mode == "other-inode" {
					path, expected = filepath.Join(filepath.Dir(s.maintenance), "other.lock"), "no"
					if err := os.WriteFile(path, nil, 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestMaintenanceAncestorRequiresActualAncestorExclusiveInode$")
			cmd.Env = append(os.Environ(), "PANASMS_MAINTENANCE=1", "GO14_ANCESTOR_LOCK="+path, "GO14_EXPECT_ANCESTOR="+expected)
			if raw, err := cmd.CombinedOutput(); err != nil {
				t.Fatal(string(raw), err)
			}
		})
	}
}

func TestCleanStartupDoesNotNeedMaintenanceAndPendingStartupDoes(t *testing.T) {
	s := executionFixture(t)
	if err := os.Remove(s.maintenance); err != nil {
		t.Fatal(err)
	}
	if err := s.recoverStartup(context.Background()); err != nil {
		t.Fatal("clean updater startup tried to acquire maintenance", err)
	}
	if err := os.Mkdir(filepath.Join(s.root, ".transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.recoverStartup(context.Background()); err == nil {
		t.Fatal("pending recovery bypassed unavailable maintenance")
	}
}

func TestResumeStartsOnlyCompatibleEnabledVerifiedServices(t *testing.T) {
	s := executionFixture(t)
	registry := Registry{}
	payload := []byte("verified fixture server")
	hash := sha256.Sum256(payload)
	for _, id := range []string{"base", "app", "disabled", "incompatible", "changed", "needs-changed"} {
		m := fixtureManifest(t)
		m["id"], m["enabled"], m["service"] = id, true, "bin/server"
		m["files"].(map[string]any)["bin/server"] = hex.EncodeToString(hash[:])
		if id == "app" {
			m["dependencies"] = map[string]any{"base": ">=1.0.0"}
		}
		if id == "needs-changed" {
			m["dependencies"] = map[string]any{"changed": ">=1.0.0"}
		}
		if id == "disabled" {
			m["enabled"] = false
		}
		if id == "incompatible" {
			m["core"] = ">=1.0.0"
		}
		if err := os.MkdirAll(filepath.Join(s.root, id, "bin"), 0755); err != nil {
			t.Fatal(err)
		}
		content := payload
		if id == "changed" {
			content = []byte("unverified replacement")
		}
		if err := os.WriteFile(filepath.Join(s.root, id, "bin/server"), content, 0755); err != nil {
			t.Fatal(err)
		}
		registry[id] = m
		if id == "base" || id == "app" {
			if err := validateManifest(m, s.core, s.architecture, false); err != nil {
				t.Fatal(id, err)
			}
			if err := s.verifyService(m); err != nil {
				t.Fatal(id, err)
			}
		}
	}
	if err := s.saveRegistry(registry); err != nil {
		t.Fatal(err)
	}
	started := []string{}
	s.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
		assertLocked(t, s.maintenance)
		assertLocked(t, filepath.Join(s.root, ".lock"))
		if len(argv) == 4 && argv[1] == "enable" {
			started = append(started, argv[3])
		}
		return nil, nil
	}
	s.health = func(context.Context, string) (map[string]any, error) { return map[string]any{}, nil }
	err := s.resume(context.Background())
	if err == nil || !strings.Contains(err.Error(), "changed, incompatible, needs-changed") || strings.Join(started, ",") != unit("base")+","+unit("app") {
		t.Fatal(started, err)
	}
	current, err := s.registry()
	a, _ := json.Marshal(registry)
	b, _ := json.Marshal(current)
	if err != nil || string(a) != string(b) {
		t.Fatal("resume changed registry intent", current, err)
	}
}

func TestUnchangedStartupRefusalKeepsPanelAndEvidenceAvailable(t *testing.T) {
	s := executionFixture(t)
	if err := os.Mkdir(filepath.Join(s.root, ".transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.maintenance); err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	if err := s.startup(context.Background(), &diagnostic); err != nil || !strings.Contains(diagnostic.String(), "maintenance lock") {
		t.Fatal(err, diagnostic.String())
	}
	if _, err := os.Stat(filepath.Join(s.root, ".transaction")); err != nil {
		t.Fatal("startup discarded evidence", err)
	}
	if err := s.recoverStartup(context.Background()); err == nil {
		t.Fatal("explicit recovery silently passed")
	}
}

func TestResumeBadDependencyIsConfinedToItsDependents(t *testing.T) {
	registry := Registry{
		"base": {"enabled": true}, "app": {"enabled": true, "dependencies": map[string]any{"base": ">=1.0.0"}},
		"broken":       {"enabled": true, "dependencies": map[string]any{"missing": ">=1.0.0"}},
		"needs-broken": {"enabled": true, "dependencies": map[string]any{"broken": ">=1.0.0"}},
		"malformed":    {"enabled": true, "dependencies": "invalid"},
		"cycle-a":      {"enabled": true, "dependencies": map[string]any{"cycle-b": ">=1.0.0"}},
		"cycle-b":      {"enabled": true, "dependencies": map[string]any{"cycle-a": ">=1.0.0"}},
	}
	for id, m := range registry {
		m["id"], m["version"] = id, "1.0.0"
	}
	order, blocked := resumeOrder(registry)
	if blocked["base"] || blocked["app"] {
		t.Fatal(blocked)
	}
	for _, id := range []string{"broken", "needs-broken", "malformed", "cycle-a", "cycle-b"} {
		if !blocked[id] {
			t.Fatal(id, blocked)
		}
	}
	joined := strings.Join(order, ",")
	if !strings.Contains(joined, "base,app") {
		t.Fatal(order)
	}
}

func TestMutatingStartupRestoreFailureStillBlocksAgentStart(t *testing.T) {
	r, _ := recoveryFixture(t, true)
	s := executionFixture(t)
	s.store, s.units, s.health, s.mounts = r.store, r.units, r.health, r.mounts
	s.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
		assertLocked(t, s.maintenance)
		assertLocked(t, filepath.Join(s.root, ".lock"))
		if argv[1] == "daemon-reload" {
			return nil, errors.New("injected reload failure")
		}
		return nil, nil
	}
	var diagnostic bytes.Buffer
	if err := s.startup(context.Background(), &diagnostic); err == nil || systemops.Unchanged(err) {
		t.Fatal("partial restore was hidden", err)
	}
	if diagnostic.Len() != 0 {
		t.Fatal("mutated failure logged as harmless")
	}
	if _, err := os.Stat(filepath.Join(s.root, ".transaction/journal.json")); err != nil {
		t.Fatal("lost recovery evidence", err)
	}
}
