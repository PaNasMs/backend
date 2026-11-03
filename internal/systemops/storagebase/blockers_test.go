package storagebase

import (
	"context"
	"fmt"
	"os"
	"panasms.local/backend/internal/systemops/folders"
	"path/filepath"
	"strings"
	"testing"
)

func TestBlockersReportNestedMountHomesAndShares(t *testing.T) {
	proc := t.TempDir()
	outer := folders.LiveMount{ID: 91, Target: "/mnt/disk"}
	inner := folders.LiveMount{ID: 92, Target: "/mnt/disk/nested"}
	err := checkBlockers(context.Background(), proc, []folders.LiveMount{outer}, []folders.LiveMount{outer, inner}, []StoragePath{{"alice", "/mnt/disk/home"}}, []StoragePath{{"media", "/mnt/disk/media"}}, []string{"/mnt/disk/export"})
	for _, want := range []string{"Mounted inside", "alice: /mnt/disk/home", "media (/mnt/disk/media)", "/mnt/disk/export"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("missing %q: %v", want, err)
		}
	}
	if err = checkBlockers(context.Background(), proc, []folders.LiveMount{inner, outer}, []folders.LiveMount{outer, inner}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}
func TestBlockersInspectDescriptorMountIdentity(t *testing.T) {
	proc := t.TempDir()
	pid := os.Getpid() + 10000
	root := filepath.Join(proc, fmt.Sprint(pid))
	os.MkdirAll(filepath.Join(root, "fdinfo"), 0700)
	os.WriteFile(filepath.Join(root, "fdinfo", "9"), []byte("pos: 0\nmnt_id: 91\n"), 0600)
	os.WriteFile(filepath.Join(root, "comm"), []byte("reader\n"), 0600)
	os.WriteFile(filepath.Join(root, "cgroup"), []byte("0::/system.slice/example.service\n"), 0600)
	err := checkBlockers(context.Background(), proc, []folders.LiveMount{{ID: 91, Target: "/mnt/disk"}}, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "reader [example.service]") || !strings.Contains(err.Error(), fmt.Sprint(pid)) {
		t.Fatalf("missing process diagnostic: %v", err)
	}
}
