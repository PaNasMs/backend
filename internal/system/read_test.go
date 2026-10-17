package system

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadDiskTemperaturesUsesOnlyCurrentReadings(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "status.json")
	status := fmt.Sprintf(`{"observedAt":%d,"disks":[{"device":"/dev/sda","state":"active","temperature":42},{"device":"/dev/sdb","state":"sleeping","temperature":38,"sleepTemperature":true},{"device":"/dev/sdc","state":"sleeping","temperature":37},{"device":"/dev/sdd","state":"active","temperature":48,"stale":true}]}`, now.Unix())
	if err := os.WriteFile(path, []byte(status), 0600); err != nil {
		t.Fatal(err)
	}
	readings := ReadDiskTemperatures(path, now)
	if len(readings) != 2 || readings["/dev/sda"] != 42 || readings["/dev/sdb"] != 38 {
		t.Fatalf("unexpected current readings: %v", readings)
	}
	if readings := ReadDiskTemperatures(path, now.Add(10*time.Second)); len(readings) != 0 {
		t.Fatalf("outdated controller status included: %v", readings)
	}
}

func TestInvalidLayouts(t *testing.T) {
	for _, v := range []map[string][]string{nil, {"huge": {}}, {"wide": {"cpu", "cpu", "cooling", "system", "users", "storage"}}, {"wide": {"bad"}}} {
		if ValidatePreferences("dark", v) == nil {
			t.Fatal("invalid layout accepted", v)
		}
	}
	if ValidatePreferences("dark", map[string][]string{"wide": {"cpu", "memory", "cooling", "system", "users", "storage"}}) != nil {
		t.Fatal("valid layout rejected")
	}
}

func TestThemes(t *testing.T) {
	for _, theme := range []string{"dark", "light", "dark-glass", "light-glass"} {
		if ValidatePreferences(theme, map[string][]string{}) != nil {
			t.Fatal("valid theme rejected", theme)
		}
	}
	for _, theme := range []string{"", "glass", "Dark", "light-solid"} {
		if ValidatePreferences(theme, map[string][]string{}) == nil {
			t.Fatal("unknown theme accepted", theme)
		}
	}
}

func TestHostMountsReplacePrivateNamespaceMounts(t *testing.T) {
	child := map[string]any{"maj:min": "179:2", "mountpoints": []string{"/", "/var/lib/panasms", "/var/tmp"}}
	disk := map[string]any{"maj:min": "179:0", "children": []any{child}}
	applyHostMounts([]map[string]any{disk}, []map[string]any{{"maj:min": "179:2", "target": "/"}, {"maj:min": "8:1", "target": "/data"}})
	points := child["mountpoints"].([]string)
	if len(points) != 1 || points[0] != "/" {
		t.Fatal(points)
	}
	if len(disk["mountpoints"].([]string)) != 0 {
		t.Fatal("unmounted disk has mountpoints")
	}
}
