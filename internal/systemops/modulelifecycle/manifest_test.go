package modulelifecycle

import (
	"encoding/json"
	"strings"
	"testing"
)

func fixtureManifest(t *testing.T) Manifest {
	t.Helper()
	m, err := decodeManifest([]byte(`{"id":"example","version":"1.0.0","api":1,"core":">=0.2.0,<0.3.0","architecture":"all","title":"Example","files":{"ui/index.js":"` + strings.Repeat("a", 64) + `"}}`))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestManifestPreservesSignedMetadataAndCoreConstraints(t *testing.T) {
	m := fixtureManifest(t)
	m["longDescription"] = "First paragraph\n\nSecond paragraph"
	m["translations"] = map[string]any{"uk": map[string]any{"longDescription": strings.Repeat("ї", 16000)}}
	m["unknownFutureField"] = map[string]any{"nested": []any{json.Number("9007199254740993"), true}}
	if err := validateManifest(m, "0.2.34", "amd64", true); err != nil {
		t.Fatal(err)
	}
	before := Registry{"example": m}
	copy, err := copyRegistry(before)
	if err != nil {
		t.Fatal(err)
	}
	copy["example"]["enabled"] = false
	if _, exists := before["example"]["enabled"]; exists {
		t.Fatal("transaction gate modified the before snapshot")
	}
	a, _ := json.Marshal(before["example"]["unknownFutureField"])
	b, _ := json.Marshal(copy["example"]["unknownFutureField"])
	if string(a) != string(b) || !strings.Contains(string(b), "9007199254740993") {
		t.Fatal("unknown metadata or exact numbers were lost")
	}
	if err := validateManifest(m, "0.3.0", "amd64", true); err == nil {
		t.Fatal("incompatible core accepted")
	}
}

func TestManifestRejectsInvalidPublicationContracts(t *testing.T) {
	tests := map[string]func(Manifest){
		"reserved":          func(m Manifest) { m["id"] = "personal-folders" },
		"architecture":      func(m Manifest) { m["architecture"] = "arm64" },
		"api":               func(m Manifest) { m["api"] = json.Number("2") },
		"boolean-api":       func(m Manifest) { m["api"] = true },
		"service":           func(m Manifest) { m["service"] = "bin/other" },
		"missing-service":   func(m Manifest) { m["service"] = "bin/server" },
		"missing-operation": func(m Manifest) { m["operations"] = "bin/server" },
		"parent-path":       func(m Manifest) { m["files"].(map[string]any)["bin/../outside"] = strings.Repeat("a", 64) },
		"absolute-path":     func(m Manifest) { m["files"].(map[string]any)["/etc/passwd"] = strings.Repeat("a", 64) },
		"checksum":          func(m Manifest) { m["files"].(map[string]any)["ui/index.js"] = "bad" },
		"missing-ui":        func(m Manifest) { m["files"] = map[string]any{"LICENSE": strings.Repeat("a", 64)} },
		"cross-handler":     func(m Manifest) { m["actions"] = []any{"user.delete"} },
		"duplicate-handler": func(m Manifest) { m["actions"] = []any{"example.run", "example.run"} },
		"widget-prefix": func(m Manifest) {
			m["widgets"] = map[string]any{"files:one": []any{json.Number("1"), json.Number("1")}}
		},
		"widget-bool":      func(m Manifest) { m["widgets"] = map[string]any{"example:one": []any{true, json.Number("1")}} },
		"package-name":     func(m Manifest) { m["packages"] = map[string]any{"--allow-remove": "1"} },
		"package-version":  func(m Manifest) { m["packages"] = map[string]any{"git": "1;reboot"} },
		"bad-dependency":   func(m Manifest) { m["dependencies"] = map[string]any{"other": ">=1.0.0,<invalid"} },
		"member-access":    func(m Manifest) { m["memberAccess"] = "true" },
		"shell-capability": func(m Manifest) { m["userShell"] = "false" },
		"translated-description": func(m Manifest) {
			m["translations"] = map[string]any{"ru": map[string]any{"longDescription": strings.Repeat("я", 16001)}}
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			m := fixtureManifest(t)
			change(m)
			if err := validateManifest(m, "0.2.34", "amd64", true); err == nil {
				t.Fatal("invalid module accepted")
			}
		})
	}
}

func TestLegacyReservedModuleRemainsManageable(t *testing.T) {
	m := fixtureManifest(t)
	m["id"] = "power"
	m["actions"] = []any{"power.run", "power.run"}
	if err := validateManifest(m, "0.2.34", "amd64", false); err != nil {
		t.Fatal(err)
	}
	if err := validateManifest(m, "0.2.34", "amd64", true); err == nil {
		t.Fatal("new core namespace installation accepted")
	}
	m["id"] = "files"
	m["actions"] = []any{"file.copy", "file.permissions"}
	if err := validateManifest(m, "0.2.34", "amd64", true); err != nil {
		t.Fatal(err)
	}
}

func TestVersionConstraintValidationDoesNotSkipInvalidTail(t *testing.T) {
	for _, value := range []string{">=1.0.0,<invalid", ">=1.0.0,", "", "~1.0.0"} {
		if _, err := satisfies("0.0.0", value); err == nil {
			t.Fatalf("invalid constraint %q accepted", value)
		}
	}
	for _, test := range []struct {
		actual, constraint string
		want               bool
	}{{"1.10.0", ">1.2.0", true}, {"1.0.0", ">=1.0.0,<2.0.0", true}, {"2.0.0", ">=1.0.0,<2.0.0", false}, {"0.1.0", "=0.1.0", true}} {
		got, err := satisfies(test.actual, test.constraint)
		if err != nil || got != test.want {
			t.Fatal(test, got, err)
		}
	}
}
