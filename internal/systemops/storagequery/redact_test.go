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
