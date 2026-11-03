package storagebase

import (
	"panasms.local/backend/internal/systemops/storagequery"
	"testing"
)

func TestPinDeviceRefusesCharacterDeviceAndNoncanonicalPath(t *testing.T) {
	for _, path := range []string{"/dev/null", "/dev/../dev/null", "/dev/disk/by-id/foreign"} {
		f, err := PinDevice(storagequery.DeviceIdentity{Path: path, DeviceNumber: "1:3"})
		if err == nil {
			f.Close()
			t.Fatalf("accepted %s", path)
		}
	}
}
