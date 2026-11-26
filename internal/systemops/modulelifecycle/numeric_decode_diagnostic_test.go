package modulelifecycle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPendingSourceNumericRepresentationDiagnostic(t *testing.T) {
	root := t.TempDir()
	s := lifecycle{keys: filepath.Join(root, "keys"), store: store{owner: uint32(os.Geteuid())}}
	row := Manifest{"id": "custom", "url": "https://fixture.invalid/", "signers": []any{"fixture"}, "limits": []any{map[string]any{"count": json.Number("9007199254740993")}}}
	raw := mustJSON(t, sourceChange{Sources: []Manifest{}, Withdraw: "custom", WithdrawRow: row})
	path := filepath.Join(root, sourceIntent)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := s.pendingSource()
	if err != nil || c == nil {
		t.Fatalf("missing journal: %v", err)
	}
	check := func(edit bool) {
		live, err := parseSources(mustJSON(t, []Manifest{row}), nil)
		if err != nil {
			t.Fatal(err)
		}
		merged, changed, err := mergeSources(live, *c)
		if edit {
			if err == nil || changed {
				t.Fatal("edited numeric row accepted")
			}
			return
		}
		if err != nil || !changed || len(merged) != 0 {
			t.Fatalf("unchanged numeric row rejected: %v", err)
		}
	}
	check(false)
	row["limits"] = []any{map[string]any{"count": json.Number("9007199254740992")}}
	check(true)
	for _, bad := range [][]byte{raw[:len(raw)-1], append(raw, ' ', '{', '}')} {
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.pendingSource(); err == nil {
			t.Fatal("accepted invalid or trailing journal data")
		}
	}
}
