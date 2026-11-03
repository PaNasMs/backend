package storagebase

import (
	"context"
	"os"
	"panasms.local/backend/internal/systemops/folders"
	"path/filepath"
	"testing"
)

func TestConfiguredAliasesProtectUnmount(t *testing.T) {
	root := t.TempDir()
	volume := filepath.Join(root, "volume")
	outside := filepath.Join(root, "outside")
	proc := filepath.Join(root, "proc")
	for _, p := range []string{volume, outside, proc, filepath.Join(volume, "alice")} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	alias := filepath.Join(root, "alias")
	if e := os.Symlink(volume, alias); e != nil {
		t.Fatal(e)
	}
	dangling := filepath.Join(root, "dangling")
	if e := os.Symlink(filepath.Join(volume, "future"), dangling); e != nil {
		t.Fatal(e)
	}
	selected := []folders.LiveMount{{ID: 91, Target: volume}}
	for _, path := range []string{filepath.Join(volume, "alice"), filepath.Join(alias, "alice"), filepath.Join(alias, "missing"), dangling} {
		for _, kind := range []string{"home", "share", "export"} {
			t.Run(kind+path, func(t *testing.T) {
				var homes, shares []StoragePath
				var exports []string
				switch kind {
				case "home":
					homes = []StoragePath{{Name: "alice", Path: path}}
				case "share":
					shares = []StoragePath{{Name: "share", Path: path}}
				case "export":
					exports = []string{path}
				}
				if e := checkBlockers(context.Background(), proc, selected, selected, homes, shares, exports); e == nil {
					t.Fatal("configured alias bypassed blocker")
				}
			})
		}
	}
	other := filepath.Join(root, "other-alias")
	if e := os.Symlink(outside, other); e != nil {
		t.Fatal(e)
	}
	if e := checkBlockers(context.Background(), proc, selected, selected, []StoragePath{{Name: "elsewhere", Path: other}}, nil, nil); e != nil {
		t.Fatal(e)
	}
	loop := filepath.Join(root, "loop")
	if e := os.Symlink(loop, loop); e != nil {
		t.Fatal(e)
	}
	if _, e := configuredInside(loop, volume); e == nil {
		t.Fatal("unresolvable configured path accepted")
	}
}
