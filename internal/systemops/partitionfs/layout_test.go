package partitionfs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagequery"
)

func fixture(t *testing.T, signature, table string) (*service, *storagequery.Preflight) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sda1"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"start": "2048", "size": "4096"} {
		if err := os.WriteFile(filepath.Join(root, "sda1", name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var rows []map[string]any
	if err := systemops.Decode([]byte(`[{"path":"/dev/sda","kname":"sda","type":"disk","size":16777216,"ro":false,"mountpoints":[],"children":[{"path":"/dev/sda1","kname":"sda1","type":"part","size":2097152,"ro":false,"mountpoints":[]}]}]`), &rows); err != nil {
		t.Fatal(err)
	}
	inv, err := storagequery.NewInventory(rows, func(s string) (string, error) { return s, nil })
	if err != nil {
		t.Fatal(err)
	}
	p := &storagequery.Preflight{Inventory: inv, System: map[string]bool{}, Carriers: map[string]bool{}, Holders: func(string) ([]string, error) { return nil, nil }}
	s := &service{sys: root, run: func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
		switch args[0] {
		case "wipefs":
			return []byte(signature), nil
		case "sfdisk":
			return []byte(table), nil
		default:
			t.Fatalf("unexpected command: %v", args)
			return nil, nil
		}
	}}
	return s, p
}

const validTable = `{"partitiontable":{"label":"gpt","sectorsize":512,"partitions":[{"node":"/dev/sda1","start":2048,"size":4096,"type":"linux"}]}}`

func TestCheckedLayoutPreservesGeometryAndRefusesUncertainSignatures(t *testing.T) {
	for _, tc := range []struct {
		name, sigs, table string
		valid             bool
	}{
		{"gpt", `{"signatures":[{"type":"gpt"},{"type":"PMBR"}]}`, validTable, true},
		{"foreign", `{"signatures":[{"type":"ext4"}]}`, validTable, false},
		{"blank-with-child", `{"signatures":[]}`, validTable, false},
		{"missing-signatures", `{}`, validTable, false},
		{"null-signature", `{"signatures":[null]}`, validTable, false},
		{"duplicate-partition", `{"signatures":[{"type":"gpt"}]}`, strings.Replace(validTable, `"size":4096`, `"size":4097`, 1), false},
		{"wrong-sector", `{"signatures":[{"type":"gpt"}]}`, strings.Replace(validTable, `"sectorsize":512`, `"sectorsize":4096`, 1), false},
		{"overflow", `{"signatures":[{"type":"gpt"}]}`, strings.Replace(validTable, `"start":2048`, `"start":18446744073709551615`, 1), false},
		{"extended", `{"signatures":[{"type":"dos"}]}`, strings.Replace(validTable, `"type":"linux"`, `"type":"0f"`, 1), false},
		{"atari-only", `{"signatures":[{"type":"atari","offset":"0x1d2"}]}`, validTable, false},
		{"overlap-atari", `{"signatures":[{"type":"dos","offset":"0x1fe"},{"type":"atari","offset":"0x1d2"}]}`, strings.Replace(validTable, `"label":"gpt"`, `"label":"dos"`, 1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, p := fixture(t, tc.sigs, tc.table)
			_, err := s.checkedLayout(context.Background(), "/dev/sda", p)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
func TestEmptyLayoutAndKernelReread(t *testing.T) {
	s, p := fixture(t, `{"signatures":[]}`, validTable)
	delete(p.Inventory.Rows, "/dev/sda1")
	delete(p.Inventory.Parents, "/dev/sda1")
	table, err := s.checkedLayout(context.Background(), "/dev/sda", p)
	if err != nil || table != nil {
		t.Fatalf("%v %v", table, err)
	}
	part := map[string]any{"node": "/dev/sda1", "start": json.Number("2048"), "size": json.Number("4096")}
	if err := s.verifyKernel(part, 512); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.sys, "sda1/size"), []byte("4000"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyKernel(part, 512); err == nil || !strings.Contains(err.Error(), "kernel has not confirmed") {
		t.Fatalf("%v", err)
	}
}
