package storagebase

import (
	"context"
	"errors"
	"os"
	"panasms.local/backend/internal/systemops"
	"path/filepath"
	"strings"
	"testing"
)

func TestFstabRetryReloadPreservesForeignEdit(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "fstab")
	old := "# preserve\nUUID=old /mnt/data ext4 rw 0 0\n"
	desired := "# preserve\nUUID=new /mnt/data ext4 rw 0 0\n"
	if err := os.WriteFile(path, []byte(old), 0644); err != nil {
		t.Fatal(err)
	}
	writes, reloads := 0, 0
	write := func(p, s string, m os.FileMode) error { writes++; return os.WriteFile(p, []byte(s), m) }
	run := func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
		if strings.Join(args, " ") != "systemctl daemon-reload" {
			t.Fatal(args)
		}
		reloads++
		if reloads == 1 {
			return nil, errors.New("injected reload failure")
		}
		return nil, nil
	}
	if err := writeFstab(context.Background(), path, os.Getuid(), Hash(old), desired, write, run, nil); err == nil {
		t.Fatal("injection ignored")
	}
	if err := writeFstab(context.Background(), path, os.Getuid(), Hash(old), desired, write, run, nil); err != nil {
		t.Fatal(err)
	}
	if writes != 1 || reloads != 2 {
		t.Fatalf("writes%d reloads%d", writes, reloads)
	}
	if err := os.WriteFile(path, []byte("foreign edit\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeFstab(context.Background(), path, os.Getuid(), Hash(old), desired, write, run, nil); err == nil {
		t.Fatal("foreign edit accepted")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "foreign edit\n" || writes != 1 || reloads != 2 {
		t.Fatal("foreign state changed")
	}
}
func TestFstabSupersedesOnlyUnavailableManagedVolume(t *testing.T) {
	old := "# original\nUUID=absent /mnt/data ext4 rw,x-systemd.device-timeout=30s 0 0\nUUID=keep /srv/keep ext4 defaults 0 2\n"
	line := "UUID=new /mnt/data ext4 ro,noauto 0 0"
	text, err := EditFstab(old, map[string]bool{"new": true}, line, func(uuid string) (bool, error) { return uuid == "absent", nil })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "# PaNasMs: superseded unavailable volume: UUID=absent") || !strings.Contains(text, "UUID=keep /srv/keep ext4 defaults 0 2") || !strings.HasSuffix(text, line+"\n") {
		t.Fatal(text)
	}
	for _, cfg := range []string{strings.Replace(old, "x-systemd.device-timeout=30s", "defaults", 1), strings.Replace(old, "UUID=absent", "/dev/sda1", 1)} {
		if _, err = EditFstab(cfg, nil, line, func(string) (bool, error) { return true, nil }); err == nil {
			t.Fatal("foreign row superseded")
		}
	}
	if _, err = EditFstab(old, nil, line, func(string) (bool, error) { return false, nil }); err == nil {
		t.Fatal("present device superseded")
	}
}

func TestFstabRemovalWithoutMatchPreservesExactBytes(t *testing.T) {
	for _, before := range []string{"", "# no final newline", "\n\n", "UUID=keep /data ext4 defaults 0 2"} {
		after, err := EditFstab(before, map[string]bool{"absent": true}, "", nil)
		if err != nil || after != before {
			t.Fatalf("%q became %q: %v", before, after, err)
		}
	}
}

func TestMountDoesNotDisplaceForeignConfigurationForSameUUID(t *testing.T) {
	before := "UUID=shared /home/archive ext4 nosuid,nodev,ro 0 2\n"
	line := "UUID=shared /mnt/selected ext4 rw,noauto,x-systemd.device-timeout=30s 0 0"
	if _, err := EditFstab(before, map[string]bool{"shared": true}, line, nil); err == nil {
		t.Fatal("foreign row silently discarded")
	}
	if out, err := EditFstab(strings.Replace(before, "nosuid,nodev,ro", "x-systemd.device-timeout=30s", 1), map[string]bool{"shared": true}, line, nil); err != nil || !strings.Contains(out, line) {
		t.Fatalf("managed row cannot move: %q %v", out, err)
	}
}

func TestDiskPreparationDoesNotOwnGenericSystemdTimeout(t *testing.T) {
	for _, opts := range []string{"x-systemd.device-timeout=30s", "rw,noatime,nofail,x-systemd.device-timeout=30s,nodev", "rw,noatime,nofail,x-systemd.device-timeout=30s # administrator-managed"} {
		row := "UUID=selected /mnt/data ext4 " + opts + " 0 0\n"
		if _, err := RemoveManagedFstabRows(row, map[string]bool{"selected": true}); err == nil {
			t.Errorf("foreign options accepted: %s", opts)
		}
	}
}
