package management

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func TestNativeHelperUsesHostNamespace(t *testing.T) {
	got := helperArgs("execute", "alice", []string{"/usr/lib/panasms/panasms-system-helper"})
	want := []string{"--mount=/proc/1/ns/mnt", "--", "/usr/lib/panasms/panasms-system-helper", "execute", "alice"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %q", got)
	}
}

func TestMigratedAndLegacyDomainsDispatchExactlyOnce(t *testing.T) {
	check := func(mode string, body any, want impl) {
		t.Helper()
		nativeHits, legacyHits := 0, 0
		native := func(context.Context, string, string, any) (json.RawMessage, error) {
			nativeHits++
			return json.RawMessage(`{}`), nil
		}
		legacyRunner := func(context.Context, string, string, any) (json.RawMessage, error) {
			legacyHits++
			return json.RawMessage(`{}`), nil
		}
		if _, err := route(native, legacyRunner)(context.Background(), mode, "alice", body); err != nil {
			t.Fatal(err)
		}
		if nativeHits+legacyHits != 1 || (want == goNative && nativeHits != 1) || (want == legacy && legacyHits != 1) {
			t.Fatalf("%s %v: native=%d legacy=%d", mode, body, nativeHits, legacyHits)
		}
	}
	for view, dst := range queryViews {
		check("query", map[string]string{"view": view}, dst)
	}
	for action, dst := range actionModules {
		for _, mode := range []string{"plan", "execute", "recover"} {
			want := dst
			if mode == "recover" && action == "module.catalog-install" {
				want = goNative
			}
			check(mode, Request{Action: action}, want)
		}
	}
	for _, action := range []string{"folder.permissions", "smb.mount", "smb.unmount", "nfs.mount", "nfs.unmount", "user.create", "user.home", "user.security", "group.edit", "homes.move", "homes.recover", "share.save", "share.remove", "share.recover", "share.account", "share.disconnect", "nfs.export", "nfs.export-remove", "system.web-port", "updates.repair", "system.reboot"} {
		if actionModules[action] != goNative {
			t.Fatal("migrated route missing", action)
		}
	}
	for _, action := range []string{"mount.attach", "mount.detach", "raid.create", "system.update.install"} {
		if actionModules[action] != legacy {
			t.Fatal("unmigrated route activated", action)
		}
	}
}
