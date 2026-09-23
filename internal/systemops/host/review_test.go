package host

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestJournalRejectsNonIntegerPriorityBeforeCommand(t *testing.T) {
	for _, target := range []string{`{"priority":"3"}`, `{"priority":3.0}`, `{"priority":3.9}`, `{"priority":true}`, `{"priority":null}`} {
		_, err := Query(context.Background(), "journal", target)
		if err == nil || err.Error() != "Number outside the allowed range" {
			t.Fatalf("%s: %v", target, err)
		}
	}
	if got, err := toInt(json.Number("3")); err != nil || got != 3 {
		t.Fatalf("integer: %d %v", got, err)
	}
}

func TestJournalTruncationKeepsUnicodeCharacters(t *testing.T) {
	text := strings.Repeat("Ж", 8193)
	if got := truncate(text, 8192); got != strings.Repeat("Ж", 8192) {
		t.Fatalf("truncated UTF-8 bytes instead of characters")
	}
}
