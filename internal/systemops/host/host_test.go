package host

import (
	"reflect"
	"testing"

	"panasms.local/backend/internal/systemops"
)

func TestPackageDetailParsing(t *testing.T) {
	cases := []struct {
		line string
		want map[string]any
	}{
		{
			"Inst example [1.0] (2.0 Debian:12 [arm64])",
			map[string]any{"name": "example", "installed": "1.0", "available": "2.0", "source": "Debian:12 [arm64]", "action": "install"},
		},
		{
			"Remv obsolete [3.4]",
			map[string]any{"name": "obsolete", "installed": "3.4", "available": "", "source": "", "action": "remove"},
		},
		{
			"Inst fresh (1.2 Debian [amd64])",
			map[string]any{"name": "fresh", "installed": "", "available": "1.2", "source": "Debian [amd64]", "action": "install"},
		},
		{
			"garbage line",
			map[string]any{"name": "garbage line", "installed": "", "available": "", "source": "", "action": "unknown"},
		},
	}
	for _, c := range cases {
		got := packageDetail(c.line)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("packageDetail(%q)\n got %v\nwant %v", c.line, got, c.want)
		}
	}
}

func TestServiceUnitPattern(t *testing.T) {
	valid := []string{"ssh.service", "my-app.service", "user@1000.service", "a.b:c.service"}
	for _, v := range valid {
		if !serviceUnit.MatchString(v) {
			t.Errorf("serviceUnit rejected valid %q", v)
		}
	}
	invalid := []string{"ssh", "app.socket", "no space.service", "path/unit.service", ""}
	for _, v := range invalid {
		if serviceUnit.MatchString(v) {
			t.Errorf("serviceUnit accepted invalid %q", v)
		}
	}
}

// TestProtectedPrefixesCoverExpected guards the exact set host.py protects, so a
// panel user can never start/stop core or OS units.
func TestProtectedPrefixesCoverExpected(t *testing.T) {
	want := []string{"panasms-", "ssh", "systemd-", "dbus", "network", "NetworkManager", "getty"}
	if !reflect.DeepEqual(protectedPrefixes, want) {
		t.Errorf("protectedPrefixes drifted: %v", protectedPrefixes)
	}
}

// TestFingerprintMatchesPythonForPowerState checks the host fingerprint for a
// power action equals common.fingerprint over [action, params, boot_id]. The
// expected hash was computed with CPython backend/management/common.fingerprint.
func TestFingerprintMatchesPythonForPowerState(t *testing.T) {
	got, err := fingerprint("system.reboot", map[string]any{}, "boot-abc")
	if err != nil {
		t.Fatal(err)
	}
	const want = "9fd1151ec005172a022c1c192c95ffdcad1a793c4e91cb78442f54b32b36ac03"
	if got != want {
		t.Errorf("power fingerprint\n got %s\nwant %s", got, want)
	}
}

// TestFingerprintPreservesUpdatesStateShape verifies the updates plan
// fingerprint matches CPython common.fingerprint over the same state map
// (packages list, packageDetails records, rebootRequired flag).
func TestFingerprintPreservesUpdatesStateShape(t *testing.T) {
	state := map[string]any{
		"packages":       []string{"Inst a [1] (2 X [arch])"},
		"packageDetails": detailList([]string{"Inst a [1] (2 X [arch])"}),
		"rebootRequired": false,
	}
	got, err := fingerprint("updates.install", map[string]any{}, state)
	if err != nil {
		t.Fatal(err)
	}
	const want = "48b08747ff3f504ff72d3be2ae4469aa528be2871695e168d15188ac45139afa"
	if got != want {
		t.Errorf("updates fingerprint\n got %s\nwant %s", got, want)
	}
}

func TestPlanRejectsUnknownAction(t *testing.T) {
	if _, err := Plan(nil, "bogus.action", nil); !systemops.IsRejected(err) {
		t.Fatalf("unknown action: got %v, want rejection", err)
	}
}

func TestExecuteRejectsUnknownAction(t *testing.T) {
	if _, err := Execute(nil, "bogus.action", nil, nil); !systemops.IsRejected(err) {
		t.Fatalf("unknown action: got %v, want rejection", err)
	}
}

func TestQueryRejectsUnknownView(t *testing.T) {
	if _, err := Query(nil, "totally-unknown", ""); !systemops.IsRejected(err) {
		t.Fatalf("unknown view: got %v, want rejection", err)
	}
}
