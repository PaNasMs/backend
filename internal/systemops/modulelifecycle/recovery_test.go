package modulelifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"panasms.local/backend/internal/systemops"
)

func recoveryFixture(t *testing.T, appEnabled bool) (recovery, *transaction) {
	t.Helper()
	s := transactionStore(t)
	units := fixtureStore(t)
	r := recovery{store: s, units: units.root, mounts: func() ([]string, error) { return []string{}, nil }, health: func(context.Context, string) (map[string]any, error) { return map[string]any{}, nil }}
	before := Registry{
		"app": {"id": "app", "version": "1.0.0", "enabled": appEnabled, "service": "bin/server", "dependencies": map[string]any{"dep": ">=1.0.0"}},
		"dep": {"id": "dep", "version": "1.0.0", "enabled": true, "service": "bin/server"},
	}
	after, err := copyRegistry(before)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"app", "dep"} {
		after[id]["version"] = "2.0.0"
	}
	state := &transaction{Schema: 1, Phase: "switching", Before: before, After: after, Affected: []string{"app", "dep"}, Units: map[string]fileSnapshot{}, Candidates: map[string]fileSnapshot{}, Payloads: map[string]payloadState{}}
	root, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	tx, err := s.transactionDirectory()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	unitDir, err := trustedDirectory(units.root, s.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer unitDir.Close()
	for _, id := range state.Affected {
		old := filepath.Join(s.root, ".transaction", "old-"+id)
		current := filepath.Join(s.root, id)
		for _, path := range []string{old, current} {
			if err = os.Mkdir(path, 0755); err != nil {
				t.Fatal(err)
			}
		}
		if err = os.WriteFile(filepath.Join(old, "payload"), []byte("old-"+id), 0644); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(current, "payload"), []byte("new-"+id), 0644); err != nil {
			t.Fatal(err)
		}
		oldIdentity, err := directoryAt(tx, "old-"+id, s.owner)
		if err != nil {
			t.Fatal(err)
		}
		newIdentity, err := directoryAt(root, id, s.owner)
		if err != nil {
			t.Fatal(err)
		}
		state.Payloads[id] = payloadState{Before: oldIdentity, Staged: newIdentity}
		unitPath := filepath.Join(units.root, unit(id))
		if err = os.WriteFile(unitPath, []byte("before-"+id), 0640); err != nil {
			t.Fatal(err)
		}
		state.Units[id], err = snapshotAt(unitDir, unit(id), s.owner)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(unitPath, []byte("candidate-"+id), 0640); err != nil {
			t.Fatal(err)
		}
		state.Candidates[id], err = snapshotAt(unitDir, unit(id), s.owner)
		if err != nil {
			t.Fatal(err)
		}
	}
	gate, err := gatedRegistry(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.saveRegistry(gate); err != nil {
		t.Fatal(err)
	}
	if err = s.saveTransaction(state); err != nil {
		t.Fatal(err)
	}
	return r, state
}

func assertOldPayloads(t *testing.T, r recovery, state *transaction) {
	t.Helper()
	for _, id := range state.Affected {
		raw, err := os.ReadFile(filepath.Join(r.root, id, "payload"))
		if err != nil || string(raw) != "old-"+id {
			t.Fatal("mixed dependency payload before service activation", id, string(raw), err)
		}
	}
	registry, err := r.registry()
	if err != nil || !registryEqual(registry, state.Before) {
		t.Fatal(registry, err)
	}
}

func TestRecoveryRestoresAllPayloadsBeforeDependencyActivationAndKeepsDisabledState(t *testing.T) {
	for _, appEnabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled-root", true: "enabled-root"}[appEnabled], func(t *testing.T) {
			r, state := recoveryFixture(t, appEnabled)
			data := filepath.Join(fixtureStore(t).root, "retained-user-data")
			if err := os.WriteFile(data, []byte("preserved"), 0600); err != nil {
				t.Fatal(err)
			}
			started := []string{}
			r.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
				if argv[1] == "enable" {
					assertOldPayloads(t, r, state)
					started = append(started, argv[len(argv)-1])
				}
				return nil, nil
			}
			if err := r.restore(context.Background(), state, nil); err != nil {
				t.Fatal(err)
			}
			want := []string{unit("dep")}
			if appEnabled {
				want = append(want, unit("app"))
			}
			if !reflect.DeepEqual(started, want) {
				t.Fatal(started, want)
			}
			assertOldPayloads(t, r, state)
			for _, id := range state.Affected {
				raw, err := os.ReadFile(filepath.Join(r.units, unit(id)))
				if err != nil || string(raw) != "before-"+id {
					t.Fatal(string(raw), err)
				}
				info, _ := os.Stat(filepath.Join(r.units, unit(id)))
				if info.Mode().Perm() != 0640 {
					t.Fatal(info.Mode())
				}
			}
			if _, err := os.Stat(filepath.Join(r.root, ".transaction")); !os.IsNotExist(err) {
				t.Fatal("completed journal retained", err)
			}
			raw, err := os.ReadFile(data)
			if err != nil || string(raw) != "preserved" {
				t.Fatal("module data altered", err)
			}
		})
	}
}

func TestRecoveryRetainsJournalAfterReloadOrServiceFailureAndRetriesConsumedBackups(t *testing.T) {
	for _, failure := range []string{"daemon-reload", "enable"} {
		t.Run(failure, func(t *testing.T) {
			r, state := recoveryFixture(t, true)
			failed := errors.New("injected service boundary")
			fail := true
			r.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
				if fail && argv[1] == failure {
					fail = false
					return nil, failed
				}
				return nil, nil
			}
			if err := r.restore(context.Background(), state, nil); !errors.Is(err, failed) {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(r.root, ".transaction/journal.json")); err != nil {
				t.Fatal("failure discarded journal", err)
			}
			assertOldPayloads(t, r, state)
			loaded, err := r.loadTransaction()
			if err != nil {
				t.Fatal(err)
			}
			if err = r.restore(context.Background(), loaded, nil); err != nil {
				t.Fatal("idempotent recovery failed after consumed backups", err)
			}
		})
	}
}

func TestRecoveryRejectsForeignEvidenceOrMountedDataBeforeCommands(t *testing.T) {
	for _, variant := range []string{"unit", "registry", "current-payload", "backup-payload", "stage-mount", "payload-mount"} {
		t.Run(variant, func(t *testing.T) {
			r, state := recoveryFixture(t, true)
			switch variant {
			case "unit":
				if err := os.WriteFile(filepath.Join(r.units, unit("app")), []byte("foreign"), 0640); err != nil {
					t.Fatal(err)
				}
			case "registry":
				registry, _ := r.registry()
				registry["foreign"] = Manifest{"id": "foreign"}
				if err := r.saveRegistry(registry); err != nil {
					t.Fatal(err)
				}
			case "current-payload", "backup-payload":
				path := filepath.Join(r.root, "app")
				if variant == "backup-payload" {
					path = filepath.Join(r.root, ".transaction/old-app")
				}
				if err := os.Rename(path, path+".foreign-saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
			case "stage-mount":
				r.mounts = func() ([]string, error) { return []string{filepath.Join(r.root, ".transaction/nested/data")}, nil }
			case "payload-mount":
				r.mounts = func() ([]string, error) { return []string{filepath.Join(r.root, "app/nested/data")}, nil }
			}
			calls := 0
			r.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) { calls++; return nil, nil }
			if err := r.restore(context.Background(), state, nil); err == nil {
				t.Fatal("foreign evidence accepted", variant)
			}
			if calls != 0 {
				t.Fatal("command before complete evidence preflight", calls)
			}
			if _, err := os.Stat(filepath.Join(r.root, ".transaction/journal.json")); err != nil {
				t.Fatal("evidence lost", err)
			}
		})
	}
}

func TestCommittedAndStagingCleanupNeverRollBackOrStartServices(t *testing.T) {
	for _, phase := range []string{"committed", "staging"} {
		t.Run(phase, func(t *testing.T) {
			r, state := recoveryFixture(t, true)
			if phase == "committed" {
				state.Committed = true
			} else {
				state.Phase = "staging"
				for _, id := range state.Affected {
					if err := os.Rename(filepath.Join(r.root, id), filepath.Join(r.root, ".transaction", id)); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(filepath.Join(r.root, ".transaction", "old-"+id), filepath.Join(r.root, id)); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(r.units, unit(id)), state.Units[id].Data, 0640); err != nil {
						t.Fatal(err)
					}
				}
				if err := r.saveRegistry(state.Before); err != nil {
					t.Fatal(err)
				}
			}
			r.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
				t.Fatal("cleanup touched service")
				return nil, nil
			}
			if err := r.restore(context.Background(), state, nil); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(r.root, "app/payload"))
			want := "new-app"
			if phase == "staging" {
				want = "old-app"
			}
			if err != nil || string(raw) != want {
				t.Fatal(string(raw), err)
			}
		})
	}
}

func TestLegacyRecoveryRestoresRetainedJournalAndDisabledModule(t *testing.T) {
	r, state := recoveryFixture(t, false)
	state.Schema = 0
	state.Phase = ""
	state.Units = nil
	state.Candidates = nil
	state.Payloads = nil
	state.After = nil
	if err := r.saveTransaction(state); err != nil {
		t.Fatal(err)
	}
	started := []string{}
	r.run = func(_ context.Context, argv []string, _ systemops.CommandOptions) ([]byte, error) {
		if argv[1] == "enable" {
			assertOldPayloads(t, r, state)
			started = append(started, argv[len(argv)-1])
		}
		return nil, nil
	}
	loaded, err := r.loadTransaction()
	if err != nil {
		t.Fatal(err)
	}
	if err = r.restore(context.Background(), loaded, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(started, []string{unit("dep")}) {
		t.Fatal(started)
	}
	raw, err := os.ReadFile(filepath.Join(r.units, unit("app")))
	if err != nil || !strings.Contains(string(raw), "KillMode=control-group") {
		t.Fatal(string(raw), err)
	}
}
