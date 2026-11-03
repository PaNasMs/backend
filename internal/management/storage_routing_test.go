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

func TestStorageMutationsUseNativeWithoutFallback(t *testing.T) {
	for _, action := range []string{"storage.recover", "storage.archive-journal", "partition.create", "partition.delete", "partition.resize", "filesystem.format", "filesystem.remove", "filesystem.resize",
		"disk.prepare", "disk.eject", "mount.attach", "mount.detach", "mount.open", "mount.settings"} {
		for _, mode := range []string{"plan", "execute", "recover"} {
			nativeHit, legacyHit := false, false
			native := func(_ context.Context, gotMode, _ string, _ any) (json.RawMessage, error) {
				nativeHit = true
				if gotMode != mode {
					t.Fatalf("%s", gotMode)
				}
				return nil, context.Canceled
			}
			_, err := route(native, recordingRunner(&legacyHit))(context.Background(), mode, "alice", map[string]any{"action": action, "params": map[string]any{"target": "/dev/example"}})
			if err == nil || !nativeHit || legacyHit {
				t.Fatalf("%s/%s err=%v native=%v legacy=%v", action, mode, err, nativeHit, legacyHit)
			}
		}
	}
}
