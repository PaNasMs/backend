package modulelifecycle

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"panasms.local/backend/internal/systemops"
)

func transactionStore(t *testing.T) store {
	t.Helper()
	s := fixtureStore(t)
	if err := os.Mkdir(filepath.Join(s.root, ".transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLegacyModuleTransactionRemainsReadableWithoutNativeFields(t *testing.T) {
	s := transactionStore(t)
	path := filepath.Join(s.root, ".transaction/journal.json")
	raw := []byte(`{"before":{"example":{"id":"example","enabled":false,"future":{"counter":9007199254740993}}},"affected":["example"],"committed":false}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	state, err := s.loadTransaction()
	if err != nil || state == nil || state.Schema != 0 || state.Before["example"]["enabled"] != false {
		t.Fatal(state, err)
	}
	state.Committed = true
	if err = s.saveTransaction(state); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var legacy struct {
		Before    Registry
		Affected  []string
		Committed bool
	}
	if err = systemops.Decode(written, &legacy); err != nil || !legacy.Committed || !reflect.DeepEqual(legacy.Before, state.Before) {
		t.Fatal(legacy, err)
	}
	if !bytes.Contains(written, []byte("9007199254740993")) || bytes.Contains(written, []byte(`"schema"`)) {
		t.Fatal(string(written))
	}
	if err = os.WriteFile(path, []byte(`{"before":{},"affected":[],"committed":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.loadTransaction(); err != nil {
		t.Fatal("legacy no-op transaction rejected", err)
	}
}

func validTransaction(owner uint32) *transaction {
	return &transaction{After: Registry{"example": {"id": "example", "enabled": true}}, Candidates: map[string]fileSnapshot{"example": {}}, Schema: 1, Phase: "staging", Before: Registry{"example": {"id": "example", "enabled": false}}, Affected: []string{"example"}, Units: map[string]fileSnapshot{"example": {Exists: true, Data: []byte("old unit\n"), Mode: 0644, UID: owner, GID: 123}}, Payloads: map[string]payloadState{"example": {Before: directoryIdentity{Exists: true, Device: 1, Inode: 42}}}}
}

func TestNativeTransactionRejectsIncompleteOrForeignEvidence(t *testing.T) {
	mutations := map[string]func(*transaction){
		"unknown-schema":    func(s *transaction) { s.Schema = 2 },
		"missing-after":     func(s *transaction) { s.After = nil },
		"missing-candidate": func(s *transaction) { delete(s.Candidates, "example") },
		"bad-candidate": func(s *transaction) {
			s.Candidates["example"] = fileSnapshot{Exists: true, UID: s.Units["example"].UID, Mode: 0666}
		},
		"staging-commit":           func(s *transaction) { s.Committed = true },
		"unknown-phase":            func(s *transaction) { s.Phase = "published" },
		"missing-before":           func(s *transaction) { s.Before = nil },
		"bad-before-key":           func(s *transaction) { s.Before["example"]["id"] = "other" },
		"duplicate-affected":       func(s *transaction) { s.Affected = append(s.Affected, "example") },
		"unsafe-affected":          func(s *transaction) { s.Affected[0] = "../escape" },
		"missing-unit":             func(s *transaction) { delete(s.Units, "example") },
		"missing-payload":          func(s *transaction) { delete(s.Payloads, "example") },
		"unknown-unit":             func(s *transaction) { s.Units["unknown"] = fileSnapshot{} },
		"foreign-unit":             func(s *transaction) { u := s.Units["example"]; u.UID++; s.Units["example"] = u },
		"writable-unit":            func(s *transaction) { u := s.Units["example"]; u.Mode = 0666; s.Units["example"] = u },
		"absent-unit-with-data":    func(s *transaction) { u := s.Units["example"]; u.Exists = false; s.Units["example"] = u },
		"missing-inode":            func(s *transaction) { s.Payloads["example"] = payloadState{Before: directoryIdentity{Exists: true}} },
		"absent-with-inode":        func(s *transaction) { s.Payloads["example"] = payloadState{Before: directoryIdentity{Inode: 42}} },
		"legacy-with-native-proof": func(s *transaction) { s.Schema = 0 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := transactionStore(t)
			state := validTransaction(s.owner)
			if err := s.saveTransaction(state); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.root, ".transaction/journal.json")
			before, _ := os.ReadFile(path)
			mutate(state)
			if err := s.saveTransaction(state); err == nil {
				t.Fatal("invalid journal persisted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("original evidence replaced on failure")
			}
			raw, _ := json.Marshal(state)
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.loadTransaction(); err == nil {
				t.Fatal("invalid journal accepted for recovery")
			}
		})
	}
}

func TestModuleSnapshotsPinOwnedFilesAndDirectoryIncarnations(t *testing.T) {
	s := fixtureStore(t)
	directory, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	absent, err := snapshotAt(directory, "example.service", s.owner)
	if err != nil || absent.Exists {
		t.Fatal(absent, err)
	}
	path := filepath.Join(s.root, "example.service")
	if err = os.WriteFile(path, []byte("unit-A\n"), 0640); err != nil {
		t.Fatal(err)
	}
	first, err := snapshotAt(directory, "example.service", s.owner)
	if err != nil || !first.Exists || first.Mode != 0640 || string(first.Data) != "unit-A\n" {
		t.Fatal(first, err)
	}
	if err = os.Symlink(path, filepath.Join(s.root, "foreign.service")); err != nil {
		t.Fatal(err)
	}
	if _, err = snapshotAt(directory, "foreign.service", s.owner); err == nil {
		t.Fatal("symlink adopted")
	}
	if err = os.Mkdir(filepath.Join(s.root, "example"), 0755); err != nil {
		t.Fatal(err)
	}
	before, err := directoryAt(directory, "example", s.owner)
	if err != nil || !before.Exists {
		t.Fatal(before, err)
	}
	if err = os.Rename(filepath.Join(s.root, "example"), filepath.Join(s.root, "old-example")); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(s.root, "example"), 0755); err != nil {
		t.Fatal(err)
	}
	after, err := directoryAt(directory, "example", s.owner)
	if err != nil || before == after {
		t.Fatal("replacement directory not distinguished", before, after, err)
	}
	backup, err := directoryAt(directory, "old-example", s.owner)
	if err != nil || backup != before {
		t.Fatal("rename lost identity", backup, before, err)
	}
	if _, err = directoryAt(directory, "../escape", s.owner); err == nil {
		t.Fatal("traversal accepted")
	}
}
