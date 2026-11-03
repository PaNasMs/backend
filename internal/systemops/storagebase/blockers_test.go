package storagebase

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
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

func TestClonedMountIDsStillIdentifyProcessFilesystem(t *testing.T) {
	for _, reference := range []string{"cwd", "root", "fd/9"} {
		t.Run(reference, func(t *testing.T) {
			proc := t.TempDir()
			root := filepath.Join(proc, "197654")
			for _, dir := range []string{"fd", "fdinfo"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			for file, data := range map[string]string{"comm": "reader", "cgroup": "", "maps": "", "fdinfo/9": "mnt_id: 17\n"} {
				if err := os.WriteFile(filepath.Join(root, file), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(proc, filepath.Join(root, reference)); err != nil {
				t.Fatal(err)
			}
			var st unix.Stat_t
			if err := unix.Stat(proc, &st); err != nil {
				t.Fatal(err)
			}
			selected := folders.LiveMount{ID: 98765, Device: fmt.Sprintf("%d:%d", unix.Major(st.Dev), unix.Minor(st.Dev)), Target: "/mnt/data"}
			err := checkBlockers(context.Background(), proc, []folders.LiveMount{selected}, nil, nil, nil, nil)
			if err == nil || !strings.Contains(err.Error(), "reader") {
				t.Fatalf("missing process in another namespace: %v", err)
			}
		})
	}
}

func TestMissingMountNamespaceRequiresConfirmedZombie(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		status string
		err    error
		skip   bool
	}{
		{"Name:\tmisleading ) R (name\nState:\tZ (zombie)\n", unix.EINVAL, true},
		{"Name:\tname ) Z\nState:\tS (sleeping)\n", unix.EINVAL, false},
		{"State:\tZ (zombie)\n", unix.EACCES, false},
		{"Name:\tzombie\n", unix.EINVAL, false},
	} {
		if err := os.WriteFile(filepath.Join(root, "status"), []byte(tc.status), 0600); err != nil {
			t.Fatal(err)
		}
		if got := mountNamespaceGone(root, tc.err); got != tc.skip {
			t.Fatalf("state=%q err=%v skip=%v", tc.status, tc.err, got)
		}
	}
}
