package folders

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestFolderVolumeBoundaries(t *testing.T) {
	base := inventory{mounts: []Mount{{Target: "/", FSType: "ext4", Options: "rw", Device: "179:2"}, {Target: "/srv/data", FSType: "ext4", Options: "rw", Device: "9:0"}}, persistent: []Mount{{Target: "/srv/data", Options: "defaults"}}, local: map[string]bool{"179:2": true, "9:0": true}, removable: map[string]bool{}}
	for _, tc := range []struct {
		name, path string
		data       bool
		change     func(*inventory)
		want       string
	}{
		{"local", "/srv/data/homes", false, func(*inventory) {}, ""},
		{"system-home", "/home", false, func(*inventory) {}, ""},
		{"system-data", "/home", true, func(*inventory) {}, "system disk"},
		{"missing", "/srv/missing", false, func(*inventory) {}, "unavailable"},
		{"readonly", "/srv/data/home", false, func(s *inventory) { s.mounts[1].Options = "ro" }, "writable"},
		{"nonpersistent", "/srv/data/home", false, func(s *inventory) { s.persistent = nil }, "automatic mounting"},
		{"noauto", "/srv/data/home", false, func(s *inventory) { s.persistent[0].Options = "rw,noauto" }, "automatic mounting"},
		{"usb", "/srv/data/home", false, func(s *inventory) { s.removable["9:0"] = true }, "USB"},
		{"unknown-device", "/srv/data/home", false, func(s *inventory) { s.mounts[1].Device = "8:123" }, "unavailable"},
		{"nested-remote", "/srv/data/remote/home", false, func(s *inventory) {
			s.mounts = append(s.mounts, Mount{Target: "/srv/data/remote", FSType: "cifs", Options: "rw"})
		}, "local Linux"},
		{"sibling", "/srv/data/remote-other", false, func(s *inventory) {
			s.mounts = append(s.mounts, Mount{Target: "/srv/data/remote", FSType: "nfs", Options: "rw"})
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			s.mounts = append([]Mount{}, base.mounts...)
			s.persistent = append([]Mount{}, base.persistent...)
			s.removable = map[string]bool{}
			tc.change(&s)
			_, err := s.volume(tc.path, tc.data)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatal(err)
			}
		})
	}
}
func TestInventoryRemovableAncestryAndBtrfsUUID(t *testing.T) {
	for _, usb := range []bool{false, true} {
		active := `{"filesystems":[{"target":"/srv/data","fstype":"btrfs","options":"rw","maj:min":"0:46","uuid":"fs"}]}`
		configured := `{"filesystems":[{"target":"/srv/data","options":"defaults"}]}`
		transport := "sata"
		if usb {
			transport = "usb"
		}
		devices := []device{{ID: "8:0", Transport: "sata", Children: []device{{ID: "8:1", FSType: "btrfs", UUID: "fs"}}}, {ID: "8:16", Transport: transport, Children: []device{{ID: "8:17", FSType: "btrfs", UUID: "fs", Children: []device{{ID: "9:0", Kind: "raid1"}}}}}}
		raw, _ := json.Marshal(map[string]any{"blockdevices": devices})
		responses := [][]byte{[]byte(active), []byte(configured), raw}
		i := 0
		s, err := readInventory(context.Background(), func(_ context.Context, args []string) ([]byte, error) { v := responses[i]; i++; return v, nil })
		if err != nil {
			t.Fatal(err)
		}
		if !s.local["0:46"] || s.removable["0:46"] != usb || s.removable["9:0"] != usb {
			t.Fatal(s)
		}
		_, err = s.volume("/srv/data/homes", true)
		if (err != nil) != usb {
			t.Fatal(err)
		}
	}
}
