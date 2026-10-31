package bootconfig

import (
	"path/filepath"
	"testing"
)

func TestWritersExcludeEachOther(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boot.lock")
	release, e := lock(path)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := lock(path); e == nil {
		second()
		release()
		t.Fatal("concurrent writer acquired lock")
	}
	release()
	next, e := lock(path)
	if e != nil {
		t.Fatal(e)
	}
	next()
}
