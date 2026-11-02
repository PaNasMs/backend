package storagequery

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMemberRedactionRecursesWithoutChangingAdminInput(t *testing.T) {
	raw := json.RawMessage(`{"devices":[{"path":"/dev/sda","serial":"private-serial","children":[{"wwn":"private-wwn","uuid":"data"}]}],"nested":{"serial":"private-other","health":null}}`)
	before := string(raw)
	redacted, err := Redact(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(redacted), "private-") || !strings.Contains(string(redacted), `"uuid":"data"`) || !strings.Contains(string(redacted), `"health":null`) {
		t.Fatalf("%s", redacted)
	}
	if string(raw) != before {
		t.Fatal("admin result was mutated")
	}
	if _, err := Redact(json.RawMessage(`invalid`)); err == nil {
		t.Fatal("malformed result accepted")
	}
}

func TestRedactionPreservesExactByteSizes(t *testing.T) {
	raw := json.RawMessage(`{"serial":"private","size":9007199254740993}`)
	result, err := Redact(raw)
	if err != nil || string(result) != `{"size":9007199254740993}` {
		t.Fatalf("%s %v", result, err)
	}
	if _, err := Redact(json.RawMessage(`{} {}`)); err == nil {
		t.Fatal("trailing result accepted")
	}
}

func TestSleepStatusSerialKeysAreNotReturnedToMembers(t *testing.T) {
	raw := json.RawMessage(`{"sleepStatus":{"private-disk:42":{"device":"/dev/sda"}},"sleepRuntime":{"total":1}}`)
	result, err := Redact(raw)
	if err != nil || strings.Contains(string(result), "private-disk") || !strings.Contains(string(result), `"sleepStatus":{}`) || !strings.Contains(string(result), `"total":1`) {
		t.Fatalf("%s %v", result, err)
	}
}
