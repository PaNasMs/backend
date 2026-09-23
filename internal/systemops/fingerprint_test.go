package systemops

import "testing"

// The expected hashes are computed by backend/management/common.fingerprint on
// the same inputs (captured with CPython 3), proving byte-for-byte parity of
// the canonical JSON: sorted keys, "," / ":" separators, \uXXXX escapes for
// non-ASCII, unescaped <>&/, integer precision and secret exclusion.
func TestFingerprintMatchesPython(t *testing.T) {
	num := func(s string) any {
		var v any
		if err := Decode([]byte(s), &v); err != nil {
			t.Fatalf("decode %q: %v", s, err)
		}
		return v
	}
	cases := []struct {
		name   string
		action string
		params map[string]any
		state  any
		want   string
	}{
		{
			name: "simple", action: "user.create",
			params: map[string]any{"name": "bob", "uid": num("1001")},
			state:  map[string]any{"exists": false},
			want:   "248a6d8e2b7633d4bd35707993dc7b801feaa9ce9fe0d5a24134319bb85ed0b8",
		},
		{
			name: "secret excluded", action: "x",
			params: map[string]any{"password": "secret", "name": "n"},
			state:  nil,
			want:   "6278f10f5b2cb3d135c37d89656c5e076d872d5cf3ca4e2d1c44774425307a3f",
		},
		{
			name: "unicode html empty", action: "u",
			params: map[string]any{"s": "café ☃ <a>&</a>"},
			state:  map[string]any{"e": []any{}},
			want:   "5762782bfaf3ba29a33aa38d7b3d919e4c95cae27662012510a4c074952ec93d",
		},
		{
			name: "big ints", action: "big",
			params: map[string]any{"size": num("18446744073709551615")},
			state:  map[string]any{"n": num("-1152921504606846976")},
			want:   "be652a47d64721911ea0f4fc64efdb0b65899147376591a9e4d12ece51210ae9",
		},
		{
			name: "bool vs int", action: "b",
			params: map[string]any{"flag": true, "num": num("1")},
			state:  map[string]any{},
			want:   "3e3e399d7d6b6b3af94623acd48cef9df2970d8325f1ea825cab8fd58f7db166",
		},
		{
			name: "astral surrogate pair", action: "astral",
			params: map[string]any{"emoji": "😀"},
			state:  "x",
			want:   "706f63ee8e7c881a856d3fb0d04f702a07c2940583f5a9603a0d2a94b80607d5",
		},
		{
			name: "nested key order", action: "nest",
			params: map[string]any{"z": num("1"), "a": []any{num("3"), num("2"), num("1")}},
			state:  map[string]any{"m": map[string]any{"y": num("2"), "x": num("1")}},
			want:   "44c1cdc016e6a1d612222ce6214502660b482acd84b7e878d72f5d5e2c36c7dd",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Fingerprint(c.action, c.params, c.state)
			if err != nil {
				t.Fatalf("Fingerprint: %v", err)
			}
			if got != c.want {
				t.Errorf("fingerprint mismatch\n got %s\nwant %s", got, c.want)
			}
		})
	}
}

func TestFingerprintExcludesAllSecretKeys(t *testing.T) {
	base, _ := Fingerprint("a", map[string]any{"name": "n"}, nil)
	for _, secret := range []string{"password", "passphrase", "currentPassword"} {
		with, _ := Fingerprint("a", map[string]any{"name": "n", secret: "x"}, nil)
		if with != base {
			t.Errorf("secret key %q changed the fingerprint", secret)
		}
	}
}
