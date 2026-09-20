package auth

import "testing"

func TestDenyUnlistedAndRoot(t *testing.T) {
	for _, name := range []string{"root", "nobody", "-u", "unlisted"} {
		if _, e := Lookup(name, map[string]bool{"root": true, "nobody": true, "-u": true}); e == nil {
			t.Fatal("unexpected authorization", name)
		}
	}
}

func TestAccessPolicy(t *testing.T) {
	p, err := AccessPolicy("sudo", "")
	if err != nil || p != nil {
		t.Fatal("sudo policy must use live group membership", err)
	}
	for _, name := range []string{"root", "nobody", "-u", ""} {
		if _, err := Lookup(name, p); err == nil {
			t.Fatal("protected or non-admin account accepted", name)
		}
	}
	for _, mode := range []string{"", "unknown"} {
		if _, err := AccessPolicy(mode, ""); err == nil {
			t.Fatal("missing policy accepted")
		}
	}
	p, err = AccessPolicy("allowlist", "alice,bob")
	if err != nil || !p["alice"] || !p["bob"] || p["other"] {
		t.Fatal("invalid allowlist")
	}
}
