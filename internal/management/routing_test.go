package management

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// recordingRunner captures whether the legacy fallback was invoked.
func recordingRunner(hit *bool) runner {
	return func(context.Context, string, string, any) (json.RawMessage, error) {
		*hit = true
		return json.RawMessage(`{"ok":true}`), nil
	}
}

func TestRouteUnknownModeRejectedBeforeDispatch(t *testing.T) {
	var hit bool
	r := route(nil, recordingRunner(&hit))
	if _, err := r(context.Background(), "bogus", "u", Request{}); err == nil {
		t.Fatal("unknown mode should be rejected")
	}
	if hit {
		t.Error("legacy runner must not run for an unknown mode")
	}
}

func TestRouteEmptyViewRejected(t *testing.T) {
	var hit bool
	r := route(nil, recordingRunner(&hit))
	if _, err := r(context.Background(), "query", "u", map[string]string{"view": ""}); !errors.Is(err, ErrUnknownView) {
		t.Fatalf("empty view: got %v, want ErrUnknownView", err)
	}
	if hit {
		t.Error("legacy runner must not run for an empty view")
	}
}

func TestRouteKnownViewGoesLegacy(t *testing.T) {
	var hit bool
	r := route(nil, recordingRunner(&hit))
	if _, err := r(context.Background(), "query", "u", map[string]string{"view": "network"}); err != nil {
		t.Fatalf("known view: %v", err)
	}
	if !hit {
		t.Error("known legacy view should reach the legacy runner")
	}
}

func TestRouteModuleExtensionViewGoesLegacy(t *testing.T) {
	// "files" is served by a module query extension, not enumerated in the
	// table, but must still route to legacy rather than be rejected.
	var hit bool
	r := route(nil, recordingRunner(&hit))
	if _, err := r(context.Background(), "query", "u", map[string]string{"view": "files"}); err != nil {
		t.Fatalf("extension view: %v", err)
	}
	if !hit {
		t.Error("module extension view should reach the legacy runner")
	}
}

func TestRoutePlanUnlistedActionGoesLegacy(t *testing.T) {
	// Unlisted actions are resolved (and possibly rejected) by the legacy
	// dispatcher, matching main.py; the router must not reject them itself.
	var hit bool
	r := route(nil, recordingRunner(&hit))
	if _, err := r(context.Background(), "plan", "u", Request{Action: "module.custom"}); err != nil {
		t.Fatalf("unlisted action: %v", err)
	}
	if !hit {
		t.Error("unlisted action should reach the legacy runner")
	}
}

func TestRouteGoNativeWithoutHandlerErrors(t *testing.T) {
	// Force a goNative route and confirm that with no registered handler the
	// router errors rather than silently reaching Python.
	queryViews["__test_go__"] = goNative
	defer delete(queryViews, "__test_go__")
	var hit bool
	r := route(nil, recordingRunner(&hit))
	if _, err := r(context.Background(), "query", "u", map[string]string{"view": "__test_go__"}); err == nil {
		t.Fatal("goNative route with nil handler must error")
	}
	if hit {
		t.Error("legacy runner must not be used as a fallback for a Go route")
	}
}

func TestRouteGoNativeDispatchesToHandler(t *testing.T) {
	queryViews["__test_go__"] = goNative
	defer delete(queryViews, "__test_go__")
	var nativeHit, legacyHit bool
	native := func(context.Context, string, string, any) (json.RawMessage, error) {
		nativeHit = true
		return json.RawMessage(`{}`), nil
	}
	r := route(native, recordingRunner(&legacyHit))
	if _, err := r(context.Background(), "query", "u", map[string]string{"view": "__test_go__"}); err != nil {
		t.Fatalf("go route: %v", err)
	}
	if !nativeHit || legacyHit {
		t.Errorf("native=%v legacy=%v; want native only", nativeHit, legacyHit)
	}
}

func TestRouteInventoryReflectsGoRoutes(t *testing.T) {
	queryViews["__test_go__"] = goNative
	defer delete(queryViews, "__test_go__")
	inv := RouteInventory()
	found := false
	for _, v := range inv.GoViews {
		if v == "__test_go__" {
			found = true
		}
	}
	if !found {
		t.Errorf("inventory GoViews missing the go-routed view: %v", inv.GoViews)
	}
}

func TestQueryViewsSortedAndComplete(t *testing.T) {
	views := QueryViews()
	if len(views) != len(queryViews) {
		t.Fatalf("QueryViews len %d != table len %d", len(views), len(queryViews))
	}
	for i := 1; i < len(views); i++ {
		if views[i-1] > views[i] {
			t.Errorf("QueryViews not sorted at %d: %q > %q", i, views[i-1], views[i])
		}
	}
}
