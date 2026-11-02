package storagequery

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestStorageOptionsLegacyParityWithoutDeviceProbes(t *testing.T) {
	root := t.TempDir()
	text := `[
 {"path":"/dev/sda","kname":"sda","type":"disk","size":100,"ro":false,"rota":true,"tran":"sata","serial":null,"mountpoints":[null],"children":[{"path":"/dev/sda1","kname":"sda1","type":"part","ro":false,"size":80,"fstype":"ext4","uuid":"root","mountpoints":["/"]}]},
 {"path":"/dev/sdb","kname":"sdb","type":"disk","size":100,"ro":false,"rota":false,"tran":"usb","serial":null,"uuid":"data","fstype":"ext4","mountpoints":["/srv/data"]},
 {"path":"/dev/mmcblk1","kname":"mmcblk1","type":"disk","size":80,"ro":true,"rota":false,"tran":"mmc","mountpoints":[]}]`
	var devices []map[string]any
	if err := json.Unmarshal([]byte(text), &devices); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sda", "sda1", "sdb", "mmcblk1"} {
		for _, dir := range []string{"slaves", "holders", "device"} {
			if err := os.MkdirAll(filepath.Join(root, "sys", name, dir), 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
	for path, data := range map[string]string{"fstab": "UUID=root / ext4 defaults 0 1\nUUID=data /srv/my\\040data ext4 noauto,x-systemd.automount,ro 0 2\n", "sys/sdb/removable": "1", "sys/sdb/device/delete": "", "sys/mmcblk1/ro": "1", "sys/mmcblk1/device/type": "SD", "sys/mmcblk1/device/name": "CARD"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s := &service{filepath.Join(root, "sys"), filepath.Join(root, "fstab"), func(context.Context) ([]map[string]any, error) { return devices, nil }, func(path string) (string, error) { return path, nil }}
	env := optionsEnvironment{filepath.Join(root, "units"), filepath.Join(root, "health"), time.Now(), func(name string) bool { return name == "mkfs.ext4" }, func() (map[string]any, error) {
		return map[string]any{"sleepSettings": map[string]any{"minutes": 0}, "sleepStatus": map[string]any{}, "sleepRuntime": map[string]any{"status": "disabled", "timerActive": true, "timerEnabled": true, "applied": 0, "total": 0}}, nil
	}}
	result, err := s.options(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := NewInventory(devices, s.resolve)
	if err != nil {
		t.Fatal(err)
	}
	expected := legacyQuery(t, root, inv, "storage-options", "", result)
	var actual any
	actualBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(actualBytes, &actual); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Go: %s\nPython: %v", actualBytes, expected)
	}
}

func legacyQuery(t *testing.T, root string, inv *Inventory, view, target string, candidate any) any {
	t.Helper()
	request, _ := json.Marshal(map[string]any{"root": root, "inventory": inv.Rows, "order": inv.Order, "view": view, "target": target, "candidate": candidate})
	cmd := exec.Command("python3", "../../../tests/storage_query_fixture.py")
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	cmd.Stdin = bytes.NewReader(request)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("legacy oracle: %v\n%s", err, output)
	}

	var expected any
	if err := json.Unmarshal(output, &expected); err != nil {
		t.Fatal(err)
	}
	return expected
}
