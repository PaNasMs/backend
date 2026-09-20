package system

import "testing"

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
