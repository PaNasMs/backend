package management

import (
	"context"
	"encoding/json"
	"testing"
)

func TestStorageReadViewsUseNativeWithoutLegacyFallback(t *testing.T) {
	for _, view := range []string{"storage-options", "raid-candidates"} {
		var nativeHit, legacyHit bool
		native := func(context.Context, string, string, any) (json.RawMessage, error) {
			nativeHit = true
			return json.RawMessage(`{}`), nil
		}
		if _, err := route(native, recordingRunner(&legacyHit))(context.Background(), "query", "alice", map[string]string{"view": view}); err != nil {
			t.Fatal(err)
		}
		if !nativeHit || legacyHit {
			t.Fatalf("%s native=%v legacy=%v", view, nativeHit, legacyHit)
		}
		if _, err := route(nil, recordingRunner(&legacyHit))(context.Background(), "query", "alice", map[string]string{"view": view}); err == nil || legacyHit {
			t.Fatal("missing native handler fell back to Python")
		}
	}
}
