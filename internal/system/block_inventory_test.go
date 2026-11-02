package system

import (
	"bytes"
	"encoding/json"
	"testing"
)

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

func TestBlockInventoryPreservesExactByteSizes(t *testing.T) {
	raw := []byte(`{"blockdevices":[{"size":9007199254740993,"ro":0}]}`)
	rows, err := decodeBlockDevices(raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(rows)
	if err != nil || !bytes.Contains(encoded, []byte("9007199254740993")) {
		t.Fatalf("%s %v", encoded, err)
	}
	if _, err := decodeBlockDevices(append(raw, []byte(`{}`)...)); err == nil {
		t.Fatal("trailing inventory accepted")
	}
}
