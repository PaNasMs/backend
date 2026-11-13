package localmounts

import (
	"panasms.local/backend/internal/systemops/storagebase"
	"reflect"
	"testing"
)

func TestParseExportsEscapes(t *testing.T) {
	got := storagebase.ParseExports([]byte("/mnt/with\\040space host(options)\n/mnt/tab\\011name host(options)\n"))
	want := []string{"/mnt/with space", "/mnt/tab\tname"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
}
func TestReadonlyOpenOptions(t *testing.T) {
	got, err := MountOptions(map[string]any{"mode": "readonly", "mountPolicy": "on-demand"})
	if err != nil || got != "ro,noatime,nofail,x-systemd.device-timeout=30s,x-systemd.automount,x-systemd.idle-timeout=10min" {
		t.Fatalf("%q %v", got, err)
	}
}
