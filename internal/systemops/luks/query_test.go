package luks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

const sampleUUID = "dd827c88-9414-426b-ad5a-88c7ea989e90"

func TestMetadataCountsOnlyBoundPasswordSlots(t *testing.T) {
	data := []byte(`{"keyslots":{"10":{"type":"luks2"},"0":{"type":"luks2"},"4":{"type":"reencrypt"}},"digests":{"0":{"keyslots":["10","4"],"segments":["0"]},"1":{"keyslots":["0"],"segments":[]}},"segments":{"0":{"type":"crypt"}}}`)
	metadata, err := parseLUKSMetadata(sampleUUID, data)
	if err != nil || !slices.Equal(metadata.Slots, []int{0, 4, 10}) || !slices.Equal(metadata.UsableSlots, []int{10}) {
		t.Fatalf("%+v, %v", metadata, err)
	}
}
func TestSlotReplacementChangesHeaderDigest(t *testing.T) {
	raw := []byte(`{"keyslots":{"0":{"type":"luks2","kdf":{"salt":"before"}}},"digests":{"0":{"keyslots":["0"],"segments":["0"]}},"segments":{"0":{"type":"crypt"}}}`)
	before, err := parseLUKSMetadata(sampleUUID, raw)
	if err != nil {
		t.Fatal(err)
	}
	after, err := parseLUKSMetadata(sampleUUID, bytes.ReplaceAll(raw, []byte("before"), []byte("after")))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(before.Slots, after.Slots) || before.HeaderDigest == after.HeaderDigest {
		t.Fatal("replaced slot must invalidate a plan")
	}
}

func TestMalformedLUKSMetadata(t *testing.T) {
	for _, data := range []string{`{}`, `{"keyslots":{"01":{}},"digests":{},"segments":{"0":{}}}`, `{"keyslots":{},"digests":{"0":{"keyslots":["0"]}},"segments":{"0":{}}}`, `{"keyslots":{},"digests":{"0":{"segments":["1"]}},"segments":{"0":{}}}`} {
		if _, err := parseLUKSMetadata(sampleUUID, []byte(data)); err == nil {
			t.Errorf("accepted %s", data)
		}
	}
}
func TestLegacyQueryRecordAndMarker(t *testing.T) {
	config, err := parseManagedConfig(sampleUUID, []byte(`{"uuid":"`+sampleUUID+`","name":"nas_data","slot":0}`))
	if err != nil {
		t.Fatal(err)
	}
	marker := "# PaNasMs " + sampleUUID
	metadata := luksMetadata{UUID: sampleUUID, Slots: []int{0, 31}}
	for _, test := range []struct {
		config    *managedConfig
		line      string
		automatic bool
		slot      string
	}{{nil, marker, false, "null"}, {config, " " + marker, false, "0"}, {config, marker, true, "0"}} {
		raw, err := queryResult("/dev/loop0", metadata, test.config, []string{test.line})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields) != 5 || string(fields["target"]) != `"/dev/loop0"` || string(fields["uuid"]) != `"`+sampleUUID+`"` || string(fields["slots"]) != "[0,31]" || string(fields["managedSlot"]) != test.slot || (string(fields["automatic"]) == "true") != test.automatic {
			t.Fatalf("query = %s", raw)
		}
	}
}
func TestMalformedRecordsCannotClaimSlotZero(t *testing.T) {
	for _, data := range []string{`{"uuid":"` + sampleUUID + `","name":"nas"}`, `{"uuid":"` + sampleUUID + `","name":"../a","slot":0}`, `{"uuid":"other","name":"nas","slot":0}`, `{"uuid":"` + sampleUUID + `","name":"nas","slot":32}`} {
		if _, err := parseManagedConfig(sampleUUID, []byte(data)); err == nil {
			t.Errorf("accepted %s", data)
		}
	}
}

func TestRealLUKS2HeaderQuery(t *testing.T) {
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		t.Skip("cryptsetup is unavailable")
	}
	path := filepath.Join(t.TempDir(), "volume.img")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = file.Truncate(32 << 20); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 48)
	if _, err = rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	ctx := context.Background()
	format := exec.CommandContext(ctx, "cryptsetup", "luksFormat", "--batch-mode", "--type", "luks2", "--pbkdf", "pbkdf2", "--iter-time", "10", "--key-file", "-", path)
	format.Stdin = bytes.NewReader(secret)
	if output, err := format.CombinedOutput(); err != nil {
		t.Fatalf("formatting temporary file: %v: %s", err, output)
	}
	metadata, err := readLUKSMetadata(ctx, fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if !luksUUIDPattern.MatchString(metadata.UUID) || !slices.Equal(metadata.Slots, []int{0}) || !slices.Equal(metadata.UsableSlots, []int{0}) {
		t.Fatalf("%+v", metadata)
	}
}
