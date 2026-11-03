package modulelifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLifecycleLockPreservesSharedInodeAndHonorsCancellation(t *testing.T) {
	s := fixtureStore(t)
	path := filepath.Join(s.root, ".lock")
	if err := os.WriteFile(path, []byte("stable inode"), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err = unix.Flock(int(reader.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, err = s.lock(ctx, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err = unix.Flock(int(reader.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	writer, err := s.lock(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err = unix.Flock(int(reader.Fd()), unix.LOCK_SH|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatal("module worker not excluded", err)
	}
	after, _ := os.Stat(path)
	raw, _ := os.ReadFile(path)
	if !os.SameFile(before, after) || string(raw) != "stable inode" {
		t.Fatal("lifecycle lock replaced or truncated")
	}
}

func TestMaintenanceCriticalWindowBlocksWorkOnlyAfterSharedStaging(t *testing.T) {
	s := fixtureStore(t)
	path := filepath.Join(s.root, "maintenance.lock")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	lease, err := acquireMaintenance(path, s.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.file.Close()
	request, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	if err = unix.Flock(int(request.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal("staging blocked API/cancellation", err)
	}
	if err = lease.critical(); err == nil {
		t.Fatal("critical window admitted active request")
	}
	if err = unix.Flock(int(request.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	// The failed conversion is abandoned by production callers; a separate new
	// operation may acquire a fresh shared lease and retry its checked plan.
	lease.file.Close()
	lease, err = acquireMaintenance(path, s.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.file.Close()
	if err = lease.critical(); err != nil {
		t.Fatal(err)
	}
	if err = unix.Flock(int(request.Fd()), unix.LOCK_SH|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatal("background work admitted during replacement", err)
	}
}

func TestMaintenanceLeaseRejectsReplacementAndUntrustedFiles(t *testing.T) {
	for _, variant := range []string{"replacement", "symlink", "writable", "hardlink"} {
		t.Run(variant, func(t *testing.T) {
			s := fixtureStore(t)
			path := filepath.Join(s.root, "maintenance.lock")
			if err := os.WriteFile(path, nil, 0644); err != nil {
				t.Fatal(err)
			}
			if variant == "replacement" {
				lease, err := acquireMaintenance(path, s.owner)
				if err != nil {
					t.Fatal(err)
				}
				defer lease.file.Close()
				if err = os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
				if err = lease.critical(); err == nil {
					t.Fatal("replacement lock accepted")
				}
				return
			}
			switch variant {
			case "symlink":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".old", path); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".linked"); err != nil {
					t.Fatal(err)
				}
			}
			if lease, err := acquireMaintenance(path, s.owner); err == nil {
				lease.file.Close()
				t.Fatal("untrusted maintenance inode accepted")
			}
		})
	}
}

func TestCriticalRetryWaitsForTransientRequestAndHonorsCancellation(t *testing.T) {
	s := executionFixture(t)
	lease, err := acquireMaintenance(s.maintenance, s.owner)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.file.Close()
	reader, err := os.Open(s.maintenance)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := unix.Flock(int(reader.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	if err := lease.waitCritical(ctx, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	cancel()
	done := make(chan error, 1)
	go func() { done <- lease.waitCritical(context.Background(), nil) }()
	select {
	case err := <-done:
		t.Fatal("reader did not hold barrier", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := unix.Flock(int(reader.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertLocked(t, s.maintenance)
}
