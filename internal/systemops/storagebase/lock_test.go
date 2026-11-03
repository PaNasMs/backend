package storagebase

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDeviceLockPreservesLegacyInodeAndCancellation(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Chmod(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(tmp, "locks")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "sda.lock")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	legacy, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if err = unix.Flock(int(legacy.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if f, err := Lock(ctx, root, "sda.lock", os.Getuid()); !errors.Is(err, context.DeadlineExceeded) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("expected cancelled lock wait: %v", err)
	}
	if err = unix.Flock(int(legacy.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	f, err := Lock(context.Background(), root, "sda.lock", os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	a, _ := legacy.Stat()
	b, _ := f.Stat()
	if !os.SameFile(a, b) {
		t.Fatal("legacy lock replaced")
	}
}
func TestLockRejectsLinksAndForeignWritableState(t *testing.T) {
	tmp := t.TempDir()
	if err := os.Chmod(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(tmp, "locks")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(root, "sda.lock")); err != nil {
		t.Fatal(err)
	}
	if f, err := Lock(context.Background(), root, "sda.lock", os.Getuid()); err == nil {
		f.Close()
		t.Fatal("link accepted")
	}
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	if f, err := Lock(context.Background(), root, "sdb.lock", os.Getuid()); err == nil {
		f.Close()
		t.Fatal("writable root accepted")
	}
}

func TestBusyReportLockReturnsImmediately(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "storage")
	held, err := lock(context.Background(), dir, "operation.lock", os.Getuid(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if f, err := lock(ctx, dir, "operation.lock", os.Getuid(), false); !errors.Is(err, unix.EWOULDBLOCK) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("report waited on an active operation: %v", err)
	}
}
