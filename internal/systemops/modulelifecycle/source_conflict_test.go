package modulelifecycle

import (
	"bytes"
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Both the live bytes and the pending decision must survive every retry.
func assertSourceConflict(t *testing.T, s lifecycle, dir *os.File) {
	t.Helper()
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir.Name(), name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	intent, rows := read(sourceIntent), read(sourceFile)
	for i := 0; i < 2; i++ {
		if err := s.recoverStartup(context.Background()); err == nil || !strings.Contains(err.Error(), "configuration conflict") {
			t.Fatalf("retry %d: wanted a conflict, got %v", i, err)
		}
		if !bytes.Equal(intent, read(sourceIntent)) || !bytes.Equal(rows, read(sourceFile)) {
			t.Fatal("conflict changed the journal or live configuration")
		}
	}
}

func TestMergeRejectsAmbiguousRow(t *testing.T) {
	row := officialSource()
	edited := maps.Clone(row)
	edited["comment"] = "local edit"
	for name, c := range map[string]sourceChange{
		"addition": {Add: row}, "withdrawal": {Withdraw: text(row, "id"), WithdrawRow: row}, "old withdrawal": {Withdraw: text(row, "id")}, "old snapshot": {Sources: []Manifest{row}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, changed, err := mergeSources([]Manifest{edited}, c); err == nil || changed {
				t.Fatal("ambiguous row accepted")
			}
		})
	}
}

func TestRecoveryLeavesMissingKeyAbsent(t *testing.T) {
	for _, visible := range []bool{false, true} {
		s, dir, c := addPending(t)
		if visible {
			if err := atomicAt(dir, sourceFile, mustJSON(t, c.Sources), 0600, s.owner); err != nil {
				t.Fatal(err)
			}
		}
		path := filepath.Join(s.keys, "catalog.pem")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		assertSourceConflict(t, s, dir)
		assertAbsent(t, path)
	}
}

func TestRecoveryLeavesEditedWithdrawalAlone(t *testing.T) {
	s, dir := withdrawalPending(t)
	rows, err := s.sources()
	if err != nil {
		t.Fatal(err)
	}
	rows[1]["note"] = "local edit"
	if err = atomicAt(dir, sourceFile, mustJSON(t, rows), 0600, s.owner); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.keys, "catalog.pem")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertSourceConflict(t, s, dir)
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) {
		t.Fatal("publisher changed during conflict", err)
	}
}
