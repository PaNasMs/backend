package luks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestManagedCrypttabRetainsUnownedRows(t *testing.T) {
	const uuid = "3bb716f4-5a44-4f12-9252-a5aea677ece2"
	cfg := &managedConfig{UUID: uuid, Name: "vault", Slot: 31}
	base := []string{"# local policy", "home UUID=other none luks", ""}
	value, err := updatedCrypttab(base, uuid, nil, "vault")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(value, "\n"), "\n")
	again, err := updatedCrypttab(lines, uuid, cfg, "vault")
	if err != nil || again != value {
		t.Fatalf("non-idempotent update: %v", err)
	}
	disabled, err := updatedCrypttab(lines, uuid, cfg, "")
	if err != nil || disabled != strings.Join(base, "\n")+"\n" {
		t.Fatalf("unexpected disable: %q %v", disabled, err)
	}
	for _, rows := range [][]string{{"vault /dev/external none luks"}, {"other UUID=" + uuid + " none luks"}, {"# PaNasMs " + uuid, "other UUID=foreign none luks"}, append(slices.Clone(lines), lines...)} {
		if _, err = updatedCrypttab(rows, uuid, cfg, "vault"); err == nil {
			t.Errorf("accepted conflicting rows: %q", rows)
		}
	}
}

func TestLastManualSlotIsProtected(t *testing.T) {
	p := &prepared{Meta: luksMetadata{Slots: []int{0, 31}, UsableSlots: []int{0, 31}}}
	_, _, err := planExtraState(context.Background(), "luks.key-remove", map[string]any{"passphrase": "fixture", "slot": 0}, p, &managedConfig{Slot: 31}, nil)
	if err == nil {
		t.Fatal("allowed removal of last manual key")
	}
}

func TestInterruptedNamedHeaderPublication(t *testing.T) {
	folder := t.TempDir()
	dir, _, err := headerDirectory(folder)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	stage := filepath.Join(folder, ".panasms-stage-header")
	if err = os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(stage, "partial"), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = publishStaged(dir, "header", strings.NewReader("complete"), -1, -1); err != nil {
		t.Fatal(err)
	}
	if err = publishStaged(dir, "header", strings.NewReader("replacement"), -1, -1); err == nil {
		t.Fatal("overwrote header")
	}
	data, err := os.ReadFile(filepath.Join(folder, "header"))
	if err != nil || string(data) != "complete" {
		t.Fatal("incorrect header")
	}
	if _, err = os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatal("staging remains", err)
	}
}

func TestHeaderPublishNoReplaceOrSymlink(t *testing.T) {
	root := t.TempDir()
	dir, _, err := headerDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err = publishFile(dir, "header", strings.NewReader("data"), -1, -1); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(root, "header"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("unsafe output: %v %v", st, err)
	}
	if err = publishFile(dir, "header", strings.NewReader("another"), -1, -1); err == nil {
		t.Fatal("replaced existing backup")
	}
	if err = os.Symlink("header", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err = publishFile(dir, "link", strings.NewReader("replacement"), -1, -1); err == nil {
		t.Fatal("replaced symlink")
	}
	data, err := os.ReadFile(filepath.Join(root, "header"))
	if err != nil || string(data) != "data" {
		t.Fatal("existing backup changed")
	}
}

// Use a disposable regular-file LUKS2 image. No device mapper or elevated
// privileges are needed for metadata, slot and header operations.
func TestDisposableLUKSKeysAndHeader(t *testing.T) {
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Skip("cryptsetup unavailable")
	}
	ctx := context.Background()
	folder := t.TempDir()
	path := filepath.Join(folder, "image")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(32 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	pass := "old fixture credential"
	newPass := "another fixture credential"
	args := []string{"luksFormat", "--batch-mode", "--type", "luks2", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--key-file", "-", path}
	if err = cryptAction(ctx, args, pass, true, nil); err != nil {
		t.Fatal(err)
	}
	meta, err := readLUKSMetadata(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	p := &prepared{Target: path, ReadPath: path, UUID: meta.UUID, Meta: meta, Extra: extraState{}}
	params := map[string]any{"passphrase": pass, "password": newPass, "slot": 0}
	if _, _, err = planExtraState(ctx, "luks.key-remove", params, p, nil, nil); err == nil {
		t.Fatal("allowed last-slot removal")
	}
	if err = unlocks(ctx, path, "incorrect password", -1); err == nil {
		t.Fatal("accepted wrong password")
	}
	if _, err = executeExtra(ctx, "luks.key-add", params, p, path, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = executeExtra(ctx, "luks.key-add", params, p, path, nil); err != nil {
		t.Fatal(err)
	}
	p.Meta, err = readLUKSMetadata(ctx, path)
	if err != nil || len(p.Meta.Slots) != 2 {
		t.Fatalf("unexpected slots: %+v %v", p.Meta, err)
	}
	if _, err = executeExtra(ctx, "luks.key-remove", params, p, path, nil); err == nil {
		t.Fatal("authorized removal with revoked slot password")
	}
	backup := filepath.Join(folder, p.UUID+".luks-header")
	if err = cryptAction(ctx, []string{"luksHeaderBackup", "--header-backup-file", backup, path}, "", false, nil); err != nil {
		t.Fatal(err)
	}
	params["passphrase"] = newPass
	if _, err = executeExtra(ctx, "luks.key-remove", params, p, path, nil); err != nil {
		t.Fatal(err)
	}
	if err = unlocks(ctx, path, pass, -1); err == nil {
		t.Fatal("revoked key still works")
	}
	params["folder"] = folder
	state, _, err := planExtraState(ctx, "luks.header-restore", params, p, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Extra = state
	if _, err = executeExtra(ctx, "luks.header-restore", params, p, path, nil); err != nil {
		t.Fatal(err)
	}
	if err = unlocks(ctx, path, pass, -1); err != nil {
		t.Fatal("restored key unavailable", err)
	}
	// A genuine cryptsetup backup can have the right UUID but no keys.
	if err = cryptAction(ctx, []string{"luksErase", "--batch-mode", path}, "", true, nil); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(backup); err != nil {
		t.Fatal(err)
	}
	if err = cryptAction(ctx, []string{"luksHeaderBackup", "--header-backup-file", backup, path}, "", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err = planExtraState(ctx, "luks.header-restore", params, p, nil, nil); err == nil {
		t.Fatal("accepted a backup without any usable key")
	}

}
