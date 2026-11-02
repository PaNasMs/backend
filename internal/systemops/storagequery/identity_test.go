package storagequery

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestIdentityRejectsReusedNameAndMissingDependencies(t *testing.T) {
	inv := fixtureInventory(t, `[{"path":"/dev/sda","kname":"sda","type":"disk","uuid":"data"}]`)
	sys := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sys, "sda/slaves"), 0700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{"sda/dev": "8:0", "sda/diskseq": "10"} {
		if err := os.WriteFile(filepath.Join(sys, path), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	first, err := inv.Identity("/dev/sda", sys)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sys, "sda/diskseq"), []byte("11"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := inv.Identity("/dev/sda", sys)
	if err != nil || reflect.DeepEqual(first, second) {
		t.Fatalf("%v %v %v", first, second, err)
	}
	if err := os.Mkdir(filepath.Join(sys, "sda/slaves/gone"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Identity("/dev/sda", sys); err == nil {
		t.Fatal("disappeared backing device accepted")
	}
}
