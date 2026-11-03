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

func TestMappedFileWithClosedDescriptorStillBlocksVolume(t *testing.T) {
	proc := t.TempDir()
	pid := os.Getpid() + 12345
	root := filepath.Join(proc, fmt.Sprint(pid))
	if err := os.MkdirAll(filepath.Join(root, "fdinfo"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{"comm": "mapped-reader\n", "maps": "00001000-00002000 r--p 00000000 103:00 899 /container-view/file (deleted)\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	selected := []folders.LiveMount{{ID: 101, Device: "259:0", Target: "/mnt/owned"}}
	if err := checkBlockers(context.Background(), proc, selected, nil, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "mapped-reader") || !strings.Contains(err.Error(), fmt.Sprint(pid)) {
		t.Fatalf("missing mapped-file blocker: %v", err)
	}
	selected[0].Device = "259:1"
	if err := checkBlockers(context.Background(), proc, selected, nil, nil, nil, nil); err != nil {
		t.Fatalf("foreign mapping prevented unmount: %v", err)
	}
}
