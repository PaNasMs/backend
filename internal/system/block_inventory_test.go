package system

import "testing"

func TestDecodeBlockInventoryMissingIsNotEmpty(t *testing.T) {
	for _, raw := range []string{`{}`, `{"blockdevices":null}`, `{"blockdevices":{}}`, `invalid`} {
		if _, err := decodeBlockDevices([]byte(raw)); err == nil {
			t.Fatal(raw)
		}
	}
	rows, err := decodeBlockDevices([]byte(`{"blockdevices":[]}`))
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatalf("%v %v", rows, err)
	}
}
