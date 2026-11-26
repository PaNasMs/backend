package modulelifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// failSync makes the nth directory sync from now on fail once; n < 1 never
// fails. It returns a counter of syncs attempted.
func failSync(t *testing.T, n int) *int {
	t.Helper()
	calls := 0
	original := syncDir
	syncDir = func(dir *os.File) error {
		calls++
		if calls == n {
			return errors.New("injected directory sync failure")
		}
		return original(dir)
	}
	t.Cleanup(func() { syncDir = original })
	return &calls
}

func sourceIDs(t *testing.T, s lifecycle) []string {
	t.Helper()
	rows, e := s.sources()
	if e != nil {
		t.Fatal(e)
	}
	ids := []string{}
	for _, m := range rows {
		ids = append(ids, text(m, "id"))
	}
	return ids
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatalf("expected %s absent: %v", path, e)
	}
}

// withdrawalPending configures legacy-repo and demo-repo with the demo key,
// then records the authorized withdrawal of demo-repo as a crash would leave it.
func withdrawalPending(t *testing.T) (lifecycle, *os.File) {
	t.Helper()
	return withdrawalPendingWithKey(t, true)
}

func withdrawalPendingWithKey(t *testing.T, present bool) (lifecycle, *os.File) {
	t.Helper()
	s, f, key := catalogFixture(t)
	ctx := context.Background()
	dir, e := s.configDir()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { dir.Close() })
	legacy := Manifest{"id": "legacy-repo", "signers": []any{"other"}, "url": "https://example.net/"}
	if e = atomicAt(dir, sourceFile, mustJSON(t, []Manifest{legacy}), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	signCatalogFixture(t, f, key, []any{})
	p := map[string]any{"url": fixtureBase}
	plan, e := s.prepare(ctx, "module.source-add", p, "alice")
	if e != nil {
		t.Fatal(e)
	}
	p["keyFingerprint"] = plan.source.Sources[1]["fingerprint"]
	if _, e = s.execute(ctx, "module.source-add", p, "alice", plan.fingerprint, nil, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if !present {
		if e = os.Remove(filepath.Join(s.keys, "catalog.pem")); e != nil {
			t.Fatal(e)
		}
	}
	plan, e = s.prepare(ctx, "module.source-remove", map[string]any{"target": "demo-repo"}, "alice")
	if e != nil {
		t.Fatal(e)
	}
	if !slices.Equal(plan.source.RemovePublishers, []string{"catalog"}) {
		t.Fatal(plan.source.RemovePublishers)
	}
	if e = atomicAt(dir, sourceIntent, mustJSON(t, plan.source), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	return s, dir
}

func addIndependent(t *testing.T, s lifecycle, dir *os.File, signer string) {
	t.Helper()
	rows, e := s.sources()
	if e != nil {
		t.Fatal(e)
	}
	rows = append(rows, Manifest{"id": "indep-repo", "signers": []any{signer}, "url": "https://example.com/indep/"})
	if e = atomicAt(dir, sourceFile, mustJSON(t, rows), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(s.keys, signer+".pem"), []byte("independent"), 0644); e != nil {
		t.Fatal(e)
	}
}

// Scenario independent-source: a source and key added after the withdrawal
// intent was written survive the replay; the withdrawal is still applied.
func TestWithdrawalReplayKeepsIndependentSource(t *testing.T) {
	s, dir := withdrawalPending(t)
	addIndependent(t, s, dir, "indep")
	for i := 0; i < 2; i++ {
		if e := s.recoverStartup(context.Background()); e != nil {
			t.Fatal(e)
		}
		if got := sourceIDs(t, s); !slices.Equal(got, []string{"legacy-repo", "indep-repo"}) {
			t.Fatalf("sources after recovery = %v", got)
		}
		if raw, e := os.ReadFile(filepath.Join(s.keys, "indep.pem")); e != nil || string(raw) != "independent" {
			t.Fatalf("independent key changed: %q %v", raw, e)
		}
		assertAbsent(t, filepath.Join(s.keys, "catalog.pem"))
		assertAbsent(t, filepath.Join(dir.Name(), sourceIntent))
	}
}

// An independent source that now trusts the withdrawn publisher keeps its key.
func TestWithdrawalReplayKeepsKeyOfIndependentSource(t *testing.T) {
	s, dir := withdrawalPending(t)
	before, e := os.ReadFile(filepath.Join(s.keys, "catalog.pem"))
	if e != nil {
		t.Fatal(e)
	}
	rows, e := s.sources()
	if e != nil {
		t.Fatal(e)
	}
	rows = append(rows, Manifest{"id": "indep-repo", "signers": []any{"catalog"}, "url": "https://example.com/indep/"})
	if e = atomicAt(dir, sourceFile, mustJSON(t, rows), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	if e = s.recoverStartup(context.Background()); e != nil {
		t.Fatal(e)
	}
	if got := sourceIDs(t, s); !slices.Equal(got, []string{"legacy-repo", "indep-repo"}) {
		t.Fatalf("sources after recovery = %v", got)
	}
	if after, e := os.ReadFile(filepath.Join(s.keys, "catalog.pem")); e != nil || !bytes.Equal(before, after) {
		t.Fatalf("key of a configured source removed: %v", e)
	}
	assertAbsent(t, filepath.Join(dir.Name(), sourceIntent))
}

// Scenario sync-failure-retry: every directory sync of the replay may fail.
// The intent survives each failure and the retry completes the withdrawal
// without touching the independent update.
func TestWithdrawalReplayRetriesAfterFailedSync(t *testing.T) {
	// Count the syncs of an undisturbed replay to cover each one.
	s, dir := withdrawalPending(t)
	addIndependent(t, s, dir, "indep")
	calls := failSync(t, 0)
	if e := s.recoverStartup(context.Background()); e != nil {
		t.Fatal(e)
	}
	total := *calls
	if total < 3 {
		t.Fatalf("expected config, key and intent syncs, got %d", total)
	}
	for n := 1; n <= total; n++ {
		t.Run("", func(t *testing.T) {
			s, dir := withdrawalPending(t)
			addIndependent(t, s, dir, "indep")
			intent, e := os.ReadFile(filepath.Join(dir.Name(), sourceIntent))
			if e != nil {
				t.Fatal(e)
			}
			failSync(t, n)
			if e := s.recoverStartup(context.Background()); e == nil {
				t.Fatalf("sync %d failure not reported", n)
			}
			retainIntent(t, s, dir, intent, n == total)
			calls := failSync(t, 0)
			if e := s.recoverStartup(context.Background()); e != nil {
				t.Fatalf("retry after failed sync %d: %v", n, e)
			}
			// Steps applied before the failure are synced again.
			if *calls != total {
				t.Fatalf("retry after failed sync %d synced %d directories, want %d", n, *calls, total)
			}
			if got := sourceIDs(t, s); !slices.Equal(got, []string{"legacy-repo", "indep-repo"}) {
				t.Fatalf("sources after retry = %v", got)
			}
			if raw, e := os.ReadFile(filepath.Join(s.keys, "indep.pem")); e != nil || string(raw) != "independent" {
				t.Fatalf("independent key changed: %q %v", raw, e)
			}
			assertAbsent(t, filepath.Join(s.keys, "catalog.pem"))
			assertAbsent(t, filepath.Join(dir.Name(), sourceIntent))
		})
	}
}

// retainIntent checks that a failed replay left its intent pending. When the
// last sync failed, the intent was unlinked but the unlink is not durable: a
// crash may bring it back, so the test restores it to replay that case.
func retainIntent(t *testing.T, s lifecycle, dir *os.File, intent []byte, last bool) {
	t.Helper()
	path := filepath.Join(dir.Name(), sourceIntent)
	if last {
		assertAbsent(t, path)
		if e := atomicAt(dir, sourceIntent, intent, 0600, s.owner); e != nil {
			t.Fatal(e)
		}
	}
	if raw, e := os.ReadFile(path); e != nil || !bytes.Equal(raw, intent) {
		t.Fatalf("intent not retained: %v", e)
	}
	if pending, e := s.pendingSource(); e != nil || pending == nil {
		t.Fatalf("pending change not reported: %v", e)
	}
}

// addPending records the authorized addition of demo-repo as a crash before
// any config or key change would leave it.
func addPending(t *testing.T) (lifecycle, *os.File, *sourceChange) {
	t.Helper()
	s, f, key := catalogFixture(t)
	dir, e := s.configDir()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { dir.Close() })
	legacy := Manifest{"id": "legacy-repo", "signers": []any{"other"}, "url": "https://example.net/"}
	if e = atomicAt(dir, sourceFile, mustJSON(t, []Manifest{legacy}), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	signCatalogFixture(t, f, key, []any{})
	plan, e := s.prepare(context.Background(), "module.source-add", map[string]any{"url": fixtureBase}, "alice")
	if e != nil {
		t.Fatal(e)
	}
	if e = atomicAt(dir, sourceIntent, mustJSON(t, plan.source), 0600, s.owner); e != nil {
		t.Fatal(e)
	}
	return s, dir, plan.source
}

func TestAdditionReplayKeepsIndependentSource(t *testing.T) {
	s, dir, change := addPending(t)
	addIndependent(t, s, dir, "indep")
	if e := s.recoverStartup(context.Background()); e != nil {
		t.Fatal(e)
	}
	if got := sourceIDs(t, s); !slices.Equal(got, []string{"legacy-repo", "indep-repo", "demo-repo"}) {
		t.Fatalf("sources after recovery = %v", got)
	}
	if raw, e := os.ReadFile(filepath.Join(s.keys, "catalog.pem")); e != nil || !bytes.Equal(raw, change.Key) {
		t.Fatalf("authorized key not installed: %v", e)
	}
	if raw, e := os.ReadFile(filepath.Join(s.keys, "indep.pem")); e != nil || string(raw) != "independent" {
		t.Fatalf("independent key changed: %q %v", raw, e)
	}
	assertAbsent(t, filepath.Join(dir.Name(), sourceIntent))
}

// A key independently installed for the same publisher is kept, and the
// source reviewed with the other key is not configured with it.
func TestAdditionReplayKeepsIndependentKey(t *testing.T) {
	s, dir, _ := addPending(t)
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		t.Fatal(e)
	}
	independent := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if e := os.WriteFile(filepath.Join(s.keys, "catalog.pem"), independent, 0644); e != nil {
		t.Fatal(e)
	}
	if e := s.recoverStartup(context.Background()); e != nil {
		t.Fatal(e)
	}
	if raw, e := os.ReadFile(filepath.Join(s.keys, "catalog.pem")); e != nil || !bytes.Equal(raw, independent) {
		t.Fatalf("independent key replaced: %v", e)
	}
	if got := sourceIDs(t, s); !slices.Equal(got, []string{"legacy-repo"}) {
		t.Fatalf("source trusted with an unreviewed key: %v", got)
	}
	assertAbsent(t, filepath.Join(dir.Name(), sourceIntent))
}

func TestAdditionReplayRetriesAfterFailedSync(t *testing.T) {
	s, dir, _ := addPending(t)
	addIndependent(t, s, dir, "indep")
	calls := failSync(t, 0)
	if e := s.recoverStartup(context.Background()); e != nil {
		t.Fatal(e)
	}
	total := *calls
	for n := 1; n <= total; n++ {
		t.Run("", func(t *testing.T) {
			s, dir, change := addPending(t)
			addIndependent(t, s, dir, "indep")
			intent, e := os.ReadFile(filepath.Join(dir.Name(), sourceIntent))
			if e != nil {
				t.Fatal(e)
			}
			failSync(t, n)
			if e := s.recoverStartup(context.Background()); e == nil {
				t.Fatalf("sync %d failure not reported", n)
			}
			retainIntent(t, s, dir, intent, n == total)
			calls := failSync(t, 0)
			if e := s.recoverStartup(context.Background()); e != nil {
				t.Fatalf("retry after failed sync %d: %v", n, e)
			}
			if *calls != total {
				t.Fatalf("retry after failed sync %d synced %d directories, want %d", n, *calls, total)
			}
			if got := sourceIDs(t, s); !slices.Equal(got, []string{"legacy-repo", "indep-repo", "demo-repo"}) {
				t.Fatalf("sources after retry = %v", got)
			}
			if raw, e := os.ReadFile(filepath.Join(s.keys, "catalog.pem")); e != nil || !bytes.Equal(raw, change.Key) {
				t.Fatalf("authorized key missing after retry: %v", e)
			}
			assertAbsent(t, filepath.Join(dir.Name(), sourceIntent))
		})
	}
}
