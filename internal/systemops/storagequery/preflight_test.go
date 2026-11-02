package storagequery

import (
	"errors"
	"strings"
	"testing"
)

func TestPreflightSystemCarrierLayoutAndMountedDescendants(t *testing.T) {
	inv := fixtureInventory(t, `[{"path":"/dev/sda","kname":"sda","type":"disk","ro":false,"children":[{"path":"/dev/sda1","kname":"sda1","type":"part","mountpoints":["/"]},{"path":"/dev/sda2","kname":"sda2","type":"part","mountpoints":[]}]}]`)
	system, carriers, err := inv.Protection(nil, func(string) ([]string, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	p := Preflight{inv, system, carriers, func(string) ([]string, error) { return nil, nil }}
	if err := p.Protected("/dev/sda", false); err == nil {
		t.Fatal("whole system disk allowed")
	}
	if err := p.Layout("/dev/sda"); err != nil {
		t.Fatal(err)
	}
	if err := p.Protected("/dev/sda1", true); err == nil {
		t.Fatal("system partition allowed")
	}
	if err := p.Protected("/dev/sda2", false); err != nil {
		t.Fatal(err)
	}
	if err := p.Unused("/dev/sda", true); err == nil || err.Error() != "Unmount file systems first" {
		t.Fatalf("%v", err)
	}
}

func TestPreflightDependencyEvidenceAndReadonly(t *testing.T) {
	inv := fixtureInventory(t, `[{"path":"/dev/sda","kname":"sda","type":"disk","ro":true,"mountpoints":[null]}]`)
	p := Preflight{inv, nil, nil, func(string) ([]string, error) { return nil, errors.New("gone") }}
	if err := p.Protected("/dev/sda", true); err == nil || err.Error() != "The device is read-only" {
		t.Fatalf("%v", err)
	}
	if err := p.Unused("/dev/sda", false); err == nil || !strings.Contains(err.Error(), "verify storage dependencies") {
		t.Fatalf("%v", err)
	}
	p.Holders = func(string) ([]string, error) { return []string{"md1", "dm-0"}, nil }
	if err := p.Unused("/dev/sda", false); err == nil || err.Error() != "Device /dev/sda is used by: dm-0, md1" {
		t.Fatalf("%v", err)
	}
}
