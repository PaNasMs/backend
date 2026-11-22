package modulelifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForeignClaimFilePreservedDuringEnrollment(t *testing.T) {
	c, serve := catalogFixture(t)
	path := filepath.Join(c.root, ".source-add-claim")
	const contents = "operator's existing file"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	params := servePendingRepository(t, &c)
	if _, err := executePlannedSource(t, c, "module.source-add", params); err != nil {
		t.Fatal(err)
	}
	key, err := c.activePublisherKey("pending")
	if err != nil || publicFingerprint(key) != params["keyFingerprint"] {
		t.Fatalf("publisher was not enrolled: %v", err)
	}
	serve("2.0.0", true)
	visibleCatalog(t, c, "2.0.0", false)
	if got, err := os.ReadFile(path); err != nil || string(got) != contents {
		t.Fatalf("foreign claim file changed: %v", err)
	}
	if after, err := os.Stat(path); err != nil || !os.SameFile(before, after) {
		t.Fatalf("foreign claim file replaced: %v", err)
	}
}

func TestRecoverMultiplePublisherClaimsPreservesUnrelatedEntries(t *testing.T) {
	c, _ := catalogFixture(t)
	first, second := strings.Repeat("a", 32), strings.Repeat("b", 32)
	claims := map[string]string{first: "one", second: "two"}
	for id, signer := range claims {
		if err := os.Symlink(claimTag+signer+":"+id, filepath.Join(c.root, claimPrefix+id)); err != nil {
			t.Fatal(err)
		}
	}
	foreign := map[string]string{
		claimPrefix + strings.Repeat("c", 32): claimTag + "other:" + first,
		claimPrefix + strings.Repeat("d", 32): "operator-link",
		claimPrefix + "archived":              claimTag + "other:" + second,
	}
	for name, value := range foreign {
		if err := os.Symlink(value, filepath.Join(c.root, name)); err != nil {
			t.Fatal(err)
		}
	}
	regular := filepath.Join(c.root, claimPrefix+strings.Repeat("e", 32))
	contents := claimTag + "other:" + strings.Repeat("e", 32)
	if err := os.WriteFile(regular, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	for _, signer := range claims {
		if fenced, err := c.publisherFenced(signer); err != nil || !fenced {
			t.Fatalf("missing early reservation for %s: %v", signer, err)
		}
	}
	if _, err := c.recoverCatalog(t.Context(), "module.source-add"); err != nil {
		t.Fatal(err)
	}
	for id, signer := range claims {
		if _, err := os.Lstat(filepath.Join(c.root, claimPrefix+id)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovery retained claim for %s: %v", signer, err)
		}
		if fenced, err := c.publisherFenced(signer); err != nil || !fenced {
			t.Fatalf("recovery lost publisher hold for %s: %v", signer, err)
		}
	}
	if fenced, err := c.publisherFenced("other"); err != nil || fenced {
		t.Fatalf("foreign entries fenced another publisher: %v", err)
	}
	if got, err := os.ReadFile(regular); err != nil || string(got) != contents {
		t.Fatalf("recovery changed ordinary file in claim namespace: %v", err)
	}
	for name, want := range foreign {
		if got, err := os.Readlink(filepath.Join(c.root, name)); err != nil || got != want {
			t.Fatalf("recovery changed foreign entry %s: %v", name, err)
		}
	}
}
