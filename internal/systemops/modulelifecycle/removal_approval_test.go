package modulelifecycle

import (
	"context"
	"crypto/sha256"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRemovalRequiresApprovalForCurrentPEM(t *testing.T) {
	s, _, _ := catalogFixture(t)
	ctx := context.Background()
	rows := []Manifest{{"id": "repo", "url": "https://example.org/", "signers": []any{"publisher"}}}
	if err := os.WriteFile(filepath.Join(filepath.Dir(s.keys), sourceFile), mustJSON(t, rows), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.keys, "publisher.pem")
	p := map[string]any{"target": "repo"}
	const action = "module.source-remove"
	previous := executionPlan(t, s, action, p) // No key at preview time.
	for _, value := range []string{"first PEM fixture", "replacement PEM fixture"} {
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
		before := snapshotState(t, s)
		if _, err := s.execute(ctx, action, p, "alice", previous, nil, func() error { return nil }); err == nil || !strings.Contains(err.Error(), "Review a new operation plan") {
			t.Fatalf("expected stale plan rejection, got %v", err)
		}
		if !maps.Equal(snapshotState(t, s), before) {
			t.Fatal("stale removal changed state")
		}
		fresh, err := s.prepare(ctx, action, p, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if fresh.fingerprint == previous || !strings.Contains(string(fresh.result), fmt.Sprintf("publisher PEM SHA256: %x", sha256.Sum256([]byte(value)))) {
			t.Fatalf("incorrect removal preview: %s", fresh.result)
		}
		previous = fresh.fingerprint
	}
	if _, err := s.execute(ctx, action, p, "alice", previous, nil, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	assertAbsent(t, path)
	if ids := sourceIDs(t, s); len(ids) != 0 {
		t.Fatal(ids)
	}
}

func TestWithdrawalReplayKeepsReplacementPEM(t *testing.T) {
	s, dir := withdrawalPending(t)
	path := filepath.Join(s.keys, "catalog.pem")
	if err := os.WriteFile(path, []byte("replacement"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.recoverStartup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "replacement" {
		t.Fatalf("replacement not preserved: %q, %v", b, err)
	}
	if ids := sourceIDs(t, s); !slices.Equal(ids, []string{"legacy-repo"}) {
		t.Fatal(ids)
	}
	assertAbsent(t, filepath.Join(dir.Name(), sourceIntent))
}
