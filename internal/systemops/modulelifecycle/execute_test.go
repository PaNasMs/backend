package modulelifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

func executionFixture(t *testing.T) lifecycle {
	t.Helper()
	s := fixtureLifecycle(t)
	s.maintenance = filepath.Join(fixtureStore(t).root, "maintenance.lock")
	if err := os.WriteFile(s.maintenance, nil, 0644); err != nil {
		t.Fatal(err)
	}
	return s
}

func executionPlan(t *testing.T, s lifecycle, action string, params map[string]any) string {
	t.Helper()
	p, err := s.prepare(context.Background(), action, params, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if p.archive != nil {
		p.archive.Close()
	}
	return p.fingerprint
}

func assertLocked(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = unix.Flock(int(file.Fd()), unix.LOCK_SH|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("maintenance admitted concurrent work at %s: %v", path, err)
	}
}

func assertReleased(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("lock leaked at %s: %v", path, err)
	}
}

func TestExecuteRollbackHoldsBothLocksThroughRestoration(t *testing.T) {
	s := executionFixture(t)
	params := map[string]any{"upload": uploadFixture(t, s)}
	fingerprint := executionPlan(t, s, "module.install", params)
	reloads, commands := 0, 0
	s.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
		commands++
		assertLocked(t, s.maintenance)
		assertLocked(t, filepath.Join(s.root, ".lock"))
		if strings.Join(argv, " ") == "systemctl daemon-reload" {
			reloads++
			if reloads == 1 {
				return nil, errors.New("injected activation reload failure")
			}
		}
		return nil, nil
	}
	if _, err := s.execute(context.Background(), "module.install", params, "alice", fingerprint, nil, func() error { return nil }); err == nil || err.Error() == incompleteRecovery {
		t.Fatal("expected recovered activation failure", err)
	}
	if reloads != 2 || commands != 2 {
		t.Fatal("rollback was not exercised", reloads, commands)
	}
	registry, err := s.registry()
	if err != nil || len(registry) != 0 {
		t.Fatal(registry, err)
	}
	for _, path := range []string{filepath.Join(s.root, "example"), filepath.Join(s.root, ".transaction"), filepath.Join(s.units, unit("example"))} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("activation artifact survived rollback", path, err)
		}
	}
	assertReleased(t, s.maintenance)
	assertReleased(t, filepath.Join(s.root, ".lock"))
}

func TestExecuteSchedulerWinsBarrierAndOnlyStagingIsRemoved(t *testing.T) {
	s := executionFixture(t)
	params := map[string]any{"upload": uploadFixture(t, s)}
	fingerprint := executionPlan(t, s, "module.install", params)
	request, err := os.Open(s.maintenance)
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	checks := 0
	_, err = s.execute(context.Background(), "module.install", params, "alice", fingerprint, nil, func() error {
		checks++
		if checks == 4 {
			if err := unix.Flock(int(request.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
				t.Fatal("staging blocked scheduler", err)
			}
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "Active requests or tasks") || checks != 4 {
		t.Fatal(checks, err)
	}
	if state, err := s.loadTransaction(); err != nil || state != nil {
		t.Fatal("private staging was not cleaned", state, err)
	}
	if registry, err := s.registry(); err != nil || len(registry) != 0 {
		t.Fatal(registry, err)
	}
	if _, err := os.Stat(filepath.Join(s.root, "example")); !os.IsNotExist(err) {
		t.Fatal("live payload changed", err)
	}
}

func TestExecuteCommitsAndRemovesOnlyOwnedUpload(t *testing.T) {
	s := executionFixture(t)
	params := map[string]any{"upload": uploadFixture(t, s)}
	fingerprint := executionPlan(t, s, "module.install", params)
	s.run = func(_ context.Context, _ []string, _ systemops.CommandOptions) ([]byte, error) {
		assertLocked(t, s.maintenance)
		assertLocked(t, filepath.Join(s.root, ".lock"))
		return nil, nil
	}
	result, err := s.execute(context.Background(), "module.install", params, "alice", fingerprint, nil, func() error { return nil })
	if err != nil || !strings.Contains(string(result), "Modules installed and enabled") {
		t.Fatal(string(result), err)
	}
	registry, err := s.registry()
	if err != nil || registry["example"]["enabled"] != true || !uploadToken.MatchString(text(registry["example"], "installation")) {
		t.Fatal(registry, err)
	}
	if raw, err := os.ReadFile(filepath.Join(s.root, "example/ui/index.js")); err != nil || string(raw) != "export default 'signed module';" {
		t.Fatal(string(raw), err)
	}
	for _, path := range []string{filepath.Join(s.root, ".transaction"), filepath.Join(s.uploads, "alice-"+text(params, "upload")+".zip")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("owned temporary artifact retained", path, err)
		}
	}
	assertReleased(t, s.maintenance)
	assertReleased(t, filepath.Join(s.root, ".lock"))
}

func serviceUpload(t *testing.T, s lifecycle) string {
	t.Helper()
	server := []byte("verified service fixture")
	hash := sha256.Sum256(server)
	raw, key := archiveFixture(t, func(m Manifest, entries *[]archiveEntry) {
		m["service"] = "bin/server"
		m["files"].(map[string]any)["bin/server"] = hex.EncodeToString(hash[:])
		*entries = append(*entries, archiveEntry{"modules/example/bin/server", server, 0755})
	}, false)
	return putUploadFixture(t, s, raw, key)
}

func installServiceBefore(t *testing.T, s lifecycle, enabled bool) Registry {
	t.Helper()
	m := fixtureManifest(t)
	m["enabled"], m["version"], m["signer"], m["service"], m["installation"] = enabled, "0.9.0", "fixture", "bin/server", strings.Repeat("b", 32)
	if err := os.Mkdir(filepath.Join(s.root, "example"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.root, "example/old-payload"), []byte("old bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.units, unit("example")), []byte("previous unit"), 0640); err != nil {
		t.Fatal(err)
	}
	before := Registry{"example": m}
	if err := s.saveRegistry(before); err != nil {
		t.Fatal(err)
	}
	return before
}

func TestExecuteFailedNewServiceRestoresOldServiceDataAndIdentity(t *testing.T) {
	s := executionFixture(t)
	params := map[string]any{"upload": serviceUpload(t, s)}
	before := installServiceBefore(t, s, true)
	s.health = func(context.Context, string) (map[string]any, error) {
		return map[string]any{"maintenanceVersion": json.Number("1"), "active": json.Number("0")}, nil
	}
	fingerprint := executionPlan(t, s, "module.install", params)
	starts := 0
	s.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
		assertLocked(t, s.maintenance)
		assertLocked(t, filepath.Join(s.root, ".lock"))
		if len(argv) == 4 && argv[1] == "enable" {
			starts++
			if starts == 1 {
				return nil, errors.New("injected new service start failure")
			}
			if raw, err := os.ReadFile(filepath.Join(s.root, "example/old-payload")); err != nil || string(raw) != "old bytes" {
				t.Fatal("old service started before code was restored", string(raw), err)
			}
			if raw, err := os.ReadFile(filepath.Join(s.units, unit("example"))); err != nil || string(raw) != "previous unit" {
				t.Fatal("old service started before unit was restored", string(raw), err)
			}
		}
		return nil, nil
	}
	if _, err := s.execute(context.Background(), "module.install", params, "alice", fingerprint, nil, func() error { return nil }); err == nil || err.Error() == incompleteRecovery {
		t.Fatal(err)
	}
	current, err := s.registry()
	if err != nil || !registryEqual(current, before) || starts != 2 {
		t.Fatal(current, starts, err)
	}
}

func TestExecuteDisabledUpgradeNeverStartsServiceOrTouchesData(t *testing.T) {
	s := executionFixture(t)
	params := map[string]any{"upload": serviceUpload(t, s)}
	before := installServiceBefore(t, s, false)
	data := filepath.Join(fixtureStore(t).root, "module-user-data")
	if err := os.WriteFile(data, []byte("user data retained"), 0600); err != nil {
		t.Fatal(err)
	}
	fingerprint := executionPlan(t, s, "module.install", params)
	s.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
		if argv[1] != "disable" && argv[1] != "daemon-reload" {
			t.Fatal("disabled module was started", argv)
		}
		return nil, nil
	}
	result, err := s.execute(context.Background(), "module.install", params, "alice", fingerprint, nil, func() error { return nil })
	if err != nil || !strings.Contains(string(result), "remains disabled") {
		t.Fatal(string(result), err)
	}
	current, err := s.registry()
	if err != nil || current["example"]["enabled"] != false || current["example"]["installation"] != before["example"]["installation"] {
		t.Fatal(current, err)
	}
	if raw, err := os.ReadFile(data); err != nil || string(raw) != "user data retained" {
		t.Fatal(string(raw), err)
	}
}

func TestExecuteRevokedAfterExtractionOnlyCleansStaging(t *testing.T) {
	s := executionFixture(t)
	params := map[string]any{"upload": uploadFixture(t, s)}
	fingerprint := executionPlan(t, s, "module.install", params)
	checks := 0
	_, err := s.execute(context.Background(), "module.install", params, "alice", fingerprint, nil, func() error {
		checks++
		if checks == 5 {
			return reject("access revoked")
		}
		return nil
	})
	if err == nil || err.Error() != "access revoked" || checks != 5 {
		t.Fatal(checks, err)
	}
	if state, err := s.loadTransaction(); err != nil || state != nil {
		t.Fatal("staging remained after safe revocation", state, err)
	}
	if _, err := os.Lstat(filepath.Join(s.root, "example")); !os.IsNotExist(err) {
		t.Fatal("revoked operation published module", err)
	}
}

func TestCommittedRecoveryCleansOnlyBackupWhileSchedulerIsActive(t *testing.T) {
	r, state := recoveryFixture(t, true)
	s := executionFixture(t)
	s.store, s.units, s.mounts = r.store, r.units, r.mounts
	state.Committed = true
	if err := s.saveRegistry(state.After); err != nil {
		t.Fatal(err)
	}
	if err := s.saveTransaction(state); err != nil {
		t.Fatal(err)
	}
	request, err := os.Open(s.maintenance)
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	if err = unix.Flock(int(request.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	params := map[string]any{}
	fingerprint := executionPlan(t, s, "module.recover", params)
	if _, err = s.execute(context.Background(), "module.recover", params, "alice", fingerprint, nil, func() error { return nil }); err != nil {
		t.Fatal("committed cleanup required interrupting active work", err)
	}
	current, err := s.registry()
	if err != nil || !registryEqual(current, state.After) {
		t.Fatal("cleanup changed committed registry", current, err)
	}
	if data, err := os.ReadFile(filepath.Join(s.root, "app/payload")); err != nil || string(data) != "new-app" {
		t.Fatal("cleanup changed committed payload", string(data), err)
	}
	if _, err := os.Lstat(filepath.Join(s.root, ".transaction")); !os.IsNotExist(err) {
		t.Fatal("cleanup did not remove backup", err)
	}
}

func TestFailedRollbackRetainsEvidenceStopsWithoutDisablingAndRetries(t *testing.T) {
	s := executionFixture(t)
	params := map[string]any{"upload": serviceUpload(t, s)}
	before := installServiceBefore(t, s, true)
	s.health = func(context.Context, string) (map[string]any, error) {
		return map[string]any{"maintenanceVersion": json.Number("1"), "active": json.Number("0")}, nil
	}
	fingerprint := executionPlan(t, s, "module.install", params)
	stops := 0
	s.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
		assertLocked(t, s.maintenance)
		assertLocked(t, filepath.Join(s.root, ".lock"))
		if argv[1] == "enable" {
			return nil, errors.New("both new and restored service start failed")
		}
		if argv[1] == "stop" {
			stops++
		}
		return nil, nil
	}
	if _, err := s.execute(context.Background(), "module.install", params, "alice", fingerprint, nil, func() error { return nil }); err == nil || err.Error() != incompleteRecovery {
		t.Fatal(err)
	}
	state, err := s.loadTransaction()
	current, registryErr := s.registry()
	if err != nil || state == nil || state.Committed || stops != 1 || registryErr != nil || !registryEqual(current, before) {
		t.Fatal(state, stops, err, registryErr)
	}
	s.run = func(_ context.Context, _ []string, _ systemops.CommandOptions) ([]byte, error) {
		assertLocked(t, s.maintenance)
		assertLocked(t, filepath.Join(s.root, ".lock"))
		return nil, nil
	}
	fingerprint = executionPlan(t, s, "module.recover", map[string]any{})
	if _, err = s.execute(context.Background(), "module.recover", map[string]any{}, "alice", fingerprint, nil, func() error { return nil }); err != nil {
		t.Fatal("retry after restored backup was consumed failed", err)
	}
	if state, err := s.loadTransaction(); err != nil || state != nil {
		t.Fatal(state, err)
	}
}

func TestUncertainCommitPreservesNewPayloadAndUntrustedJournal(t *testing.T) {
	s := executionFixture(t)
	params := map[string]any{"upload": serviceUpload(t, s)}
	fingerprint := executionPlan(t, s, "module.install", params)
	s.health = func(context.Context, string) (map[string]any, error) { return map[string]any{}, nil }
	stops := 0
	s.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
		assertLocked(t, s.maintenance)
		assertLocked(t, filepath.Join(s.root, ".lock"))
		if argv[1] == "enable" {
			if err := os.Link(filepath.Join(s.root, ".transaction/journal.json"), filepath.Join(s.root, "preserved-journal")); err != nil {
				t.Fatal(err)
			}
		}
		if argv[1] == "disable" {
			t.Fatal("uncertain commit changed enable-state")
		}
		if argv[1] == "stop" {
			stops++
		}
		return nil, nil
	}
	if _, err := s.execute(context.Background(), "module.install", params, "alice", fingerprint, nil, func() error { return nil }); err == nil || err.Error() != incompleteRecovery || stops != 1 {
		t.Fatal(stops, err)
	}
	if _, err := os.Stat(filepath.Join(s.root, "example/bin/server")); err != nil {
		t.Fatal("uncertain commit removed new payload", err)
	}
	if _, err := s.loadTransaction(); err == nil {
		t.Fatal("untrusted journal was consumed")
	}
	if _, err := os.Lstat(filepath.Join(s.root, ".transaction/journal.json")); err != nil {
		t.Fatal("commit evidence deleted", err)
	}
}

func TestCommitReadbackMustMatchAllTransactionEvidence(t *testing.T) {
	s := executionFixture(t)
	state := validTransaction(s.owner)
	state.Phase = "switching"
	state.Committed = true
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"committed", "unit", "payload", "phase", "affected"} {
		t.Run(field, func(t *testing.T) {
			var recorded transaction
			if err := systemops.Decode(raw, &recorded); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "committed":
				recorded.Committed = false
			case "unit":
				recorded.Candidates[recorded.Affected[0]] = fileSnapshot{Exists: true, Data: []byte("foreign"), Mode: 0644, UID: s.owner}
			case "payload":
				recorded.Payloads[recorded.Affected[0]] = payloadState{Staged: directoryIdentity{Exists: true, Device: 1, Inode: 2}}
			case "phase":
				recorded.Phase = "staging"
			case "affected":
				recorded.Affected = append(recorded.Affected, "different")
			}
			if matchesCommitIntent(state, &recorded) != (field == "committed") {
				t.Fatal("readback trusted evidence from another activation", field)
			}
		})
	}
}

func TestExecuteRefreshesInstalledCoreAfterAcquiringMaintenance(t *testing.T) {
	s := executionFixture(t)
	s.coreFile = filepath.Join(fixtureStore(t).root, "VERSION")
	if err := os.WriteFile(s.coreFile, []byte(s.core), 0644); err != nil {
		t.Fatal(err)
	}
	params := map[string]any{"upload": uploadFixture(t, s)}
	fingerprint := executionPlan(t, s, "module.install", params)
	if err := os.WriteFile(s.coreFile, []byte("0.2.35"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := s.execute(context.Background(), "module.install", params, "alice", fingerprint, nil, func() error { return nil })
	if err == nil || !systemops.Unchanged(err) || err.Error() != "State has changed. Review a new operation plan." {
		t.Fatal("stale core metadata authorized a mutation", err)
	}
	if state, err := s.loadTransaction(); err != nil || state != nil {
		t.Fatal("stale core created a transaction", state, err)
	}
}

func TestExecuteRechecksRevokedReplacedAndUnsafePublisherAfterStaging(t *testing.T) {
	for _, change := range []string{"removed", "replaced", "unsafe"} {
		t.Run(change, func(t *testing.T) {
			s := executionFixture(t)
			params := map[string]any{"upload": uploadFixture(t, s)}
			fingerprint := executionPlan(t, s, "module.install", params)
			checks := 0
			_, err := s.execute(context.Background(), "module.install", params, "alice", fingerprint, nil, func() error {
				checks++
				if checks == 4 {
					path := filepath.Join(s.keys, "fixture.pem")
					switch change {
					case "removed":
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
					case "unsafe":
						if err := os.Chmod(path, 0666); err != nil {
							t.Fatal(err)
						}
					case "replaced":
						key, _, err := ed25519.GenerateKey(rand.Reader)
						if err != nil {
							t.Fatal(err)
						}
						der, err := x509.MarshalPKIXPublicKey(key)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0644); err != nil {
							t.Fatal(err)
						}
					}
				}
				return nil
			})
			if err == nil || err.Error() != "Module publisher trust changed. Review a new operation plan." || checks != 5 {
				t.Fatal("revoked key authorized activation", checks, err)
			}
			if state, err := s.loadTransaction(); err != nil || state != nil {
				t.Fatal("revoked publisher staging was not cleaned", state, err)
			}
			if _, err := os.Lstat(filepath.Join(s.root, "example")); !os.IsNotExist(err) {
				t.Fatal("revoked publisher payload activated", err)
			}
		})
	}
}

func TestInterruptedRecoveryRefusesActiveWorkWithoutChangingEvidence(t *testing.T) {
	r, _ := recoveryFixture(t, true)
	s := executionFixture(t)
	s.store, s.units, s.mounts = r.store, r.units, r.mounts
	before, err := os.ReadFile(filepath.Join(s.root, ".transaction/journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := os.Open(s.maintenance)
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	if err := unix.Flock(int(request.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	params := map[string]any{}
	fingerprint := executionPlan(t, s, "module.recover", params)
	if _, err := s.execute(context.Background(), "module.recover", params, "alice", fingerprint, nil, func() error { return nil }); err == nil || !systemops.Unchanged(err) || !strings.Contains(err.Error(), "Active requests or tasks") {
		t.Fatal("live rollback admitted active work", err)
	}
	after, err := os.ReadFile(filepath.Join(s.root, ".transaction/journal.json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("blocked recovery changed its evidence", err)
	}
	for _, id := range []string{"app", "dep"} {
		if data, err := os.ReadFile(filepath.Join(s.root, id, "payload")); err != nil || string(data) != "new-"+id {
			t.Fatal("blocked recovery changed active code", id, err)
		}
	}
}

func TestExecuteEnableDisableRemoveRetainsPayloadAndInstallationUntilRemoval(t *testing.T) {
	s := executionFixture(t)
	m := fixtureManifest(t)
	m["enabled"], m["service"], m["installation"] = true, "bin/server", strings.Repeat("b", 32)
	files := map[string]any{}
	for relative, content := range map[string][]byte{"ui/index.js": []byte("fixture UI"), "bin/server": []byte("fixture server")} {
		path := filepath.Join(s.root, "example", relative)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0755); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		files[relative] = hex.EncodeToString(sum[:])
	}
	m["files"] = files
	if err := s.saveRegistry(Registry{"example": m}); err != nil {
		t.Fatal(err)
	}
	if err := writeUnit(s.root, s.units, m, s.owner); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(s.root, "example"))
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(t.TempDir(), "user-data")
	if err := os.WriteFile(data, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	s.health = func(context.Context, string) (map[string]any, error) {
		return map[string]any{"active": json.Number("0"), "maintenanceVersion": json.Number("1")}, nil
	}
	s.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
		assertLocked(t, s.maintenance)
		assertLocked(t, filepath.Join(s.root, ".lock"))
		return nil, nil
	}
	for _, action := range []string{"module.disable", "module.enable", "module.remove"} {
		params := map[string]any{"target": "example"}
		fp := executionPlan(t, s, action, params)
		if _, err := s.execute(context.Background(), action, params, "alice", fp, nil, func() error { return nil }); err != nil {
			t.Fatal(action, err)
		}
		current, err := s.registry()
		if err != nil {
			t.Fatal(err)
		}
		if action == "module.remove" {
			if current["example"] != nil {
				t.Fatal(current)
			}
			for _, path := range []string{filepath.Join(s.root, "example"), filepath.Join(s.units, unit("example"))} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal(path, err)
				}
			}
		} else {
			after, err := os.Stat(filepath.Join(s.root, "example"))
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("non-install replaced payload", err)
			}
			if current["example"]["installation"] != m["installation"] || current["example"]["enabled"] != (action == "module.enable") {
				t.Fatal(current)
			}
		}
	}
	catalog, err := os.ReadFile(filepath.Join(s.root, "catalog.json"))
	if err != nil || !bytes.Contains(catalog, []byte("example")) {
		t.Fatal("widget metadata not retained", err, string(catalog))
	}
	raw, err := os.ReadFile(data)
	if err != nil || string(raw) != "preserve" {
		t.Fatal("retained user data changed", err)
	}
}

func TestCriticalRetryRejectsCoreChangeAcrossDroppedSharedLease(t *testing.T) {
	s := executionFixture(t)
	s.coreFile = filepath.Join(fixtureStore(t).root, "VERSION")
	if err := os.WriteFile(s.coreFile, []byte(s.core), 0644); err != nil {
		t.Fatal(err)
	}
	params := map[string]any{"upload": uploadFixture(t, s)}
	fp := executionPlan(t, s, "module.install", params)
	finished := make(chan error, 1)
	checks := 0
	_, err := s.execute(context.Background(), "module.install", params, "alice", fp, nil, func() error {
		checks++
		if checks == 4 {
			reader, err := os.Open(s.maintenance)
			if err != nil {
				return err
			}
			if err := unix.Flock(int(reader.Fd()), unix.LOCK_SH); err != nil {
				reader.Close()
				return err
			}
			go func() {
				time.Sleep(40 * time.Millisecond)
				changed := os.WriteFile(s.coreFile, []byte("0.2.35"), 0644)
				unlocked := unix.Flock(int(reader.Fd()), unix.LOCK_UN)
				closed := reader.Close()
				finished <- errors.Join(changed, unlocked, closed)
			}()
		}
		return nil
	})
	if checks != 4 || err == nil || err.Error() != "State has changed. Review a new operation plan." {
		t.Fatal(checks, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if state, err := s.loadTransaction(); err != nil || state != nil {
		t.Fatal("private staging not cleaned", state, err)
	}
	if _, err := os.Stat(filepath.Join(s.root, "example")); !os.IsNotExist(err) {
		t.Fatal("core drift activated module", err)
	}
}

func TestRecoveryRetryRechecksOriginalAuthorizationBeforeRestoration(t *testing.T) {
	r, _ := recoveryFixture(t, true)
	s := executionFixture(t)
	s.store, s.units, s.health, s.mounts = r.store, r.units, r.health, r.mounts
	s.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
		t.Fatal("revoked recovery mutated services")
		return nil, nil
	}
	before, err := os.ReadFile(filepath.Join(s.root, ".transaction/journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	fp := executionPlan(t, s, "module.recover", map[string]any{})
	reader, err := os.Open(s.maintenance)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := unix.Flock(int(reader.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	var revoked atomic.Bool
	done := make(chan error, 1)
	calls := 0
	_, err = s.execute(context.Background(), "module.recover", map[string]any{}, "alice", fp, nil, func() error {
		calls++
		if revoked.Load() {
			return reject("revoked")
		}
		if calls == 3 {
			go func() {
				time.Sleep(40 * time.Millisecond)
				revoked.Store(true)
				done <- unix.Flock(int(reader.Fd()), unix.LOCK_UN)
			}()
		}
		return nil
	})
	if calls != 4 || err == nil || err.Error() != "revoked" || !systemops.Unchanged(err) {
		t.Fatal(calls, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(s.root, ".transaction/journal.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused recovery changed journal", err)
	}
}
