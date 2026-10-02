package maintenance

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSharedAndExclusiveLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	os.WriteFile(path, nil, 0644)
	release, err := AcquirePath(path)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := os.Open(path)
	defer other.Close()
	if syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
		t.Fatal("maintenance interrupted shared operation")
	}
	release()
	if err := syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if release, err := AcquirePath(path); err == nil {
		release()
		t.Fatal("new operation entered maintenance")
	}
}
