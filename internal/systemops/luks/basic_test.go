package luks

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"panasms.local/backend/internal/systemops"
)

func TestBasicPassphraseIsPassedOnlyThroughStdin(t *testing.T) {
	dir := t.TempDir()
	const script = "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$(dirname \"$0\")/args\"\ncat > \"$(dirname \"$0\")/stdin\"\n"
	if err := os.WriteFile(filepath.Join(dir, "cryptsetup"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "udevadm"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	const secret = "example secret with space\nand Unicode —"
	p := &prepared{ReadPath: "/proc/0/fd/4", Target: "/dev/loop0", Name: "data"}
	for _, action := range []string{"luks.create", "luks.open"} {
		result, err := applyBasic(context.Background(), action, map[string]any{"passphrase": secret}, p, nil)
		if err != nil {
			t.Fatal(err)
		}
		args, err := os.ReadFile(filepath.Join(dir, "args"))
		if err != nil {
			t.Fatal(err)
		}
		input, err := os.ReadFile(filepath.Join(dir, "stdin"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(args, []byte(secret)) || string(input) != secret || !strings.Contains(string(args), "--key-file\n-\n"+p.ReadPath+"\n") || result["target"] != p.Target {
			t.Fatal("unexpected secret transport or target")
		}
	}
}

func TestBasicOpenRedactsFailuresAndReportsNoChangesOnlyBeforeActivation(t *testing.T) {
	for _, tc := range []struct {
		check, activate, want string
		unchanged             bool
	}{
		{"2", "0", "password", true},
		{"0", "5", "busy", false},
		{"0", "2", "code 2", false},
	} {
		dir := t.TempDir()
		script := "#!/bin/sh\ncat >&2\nif [ \"$2\" = --test-passphrase ]; then exit " + tc.check + "; fi\nexit " + tc.activate + "\n"
		if err := os.WriteFile(filepath.Join(dir, "cryptsetup"), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
		_, err := applyBasic(context.Background(), "luks.open", map[string]any{"passphrase": "secret marker"}, &prepared{}, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "secret marker") || systemops.Unchanged(err) != tc.unchanged {
			t.Fatalf("unexpected failure: %v", err)
		}
	}
}

func TestCompletedLUKSOperationSurvivesInventoryFailure(t *testing.T) {
	dir := t.TempDir()
	for name, script := range map[string]string{"cryptsetup": "#!/bin/sh\nexit 0\n", "udevadm": "#!/bin/sh\nexit 1\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	p := &prepared{Target: "/dev/loop0", ReadPath: "/proc/0/fd/4", Name: "data"}
	for _, action := range []string{"luks.create", "luks.open"} {
		result, err := applyBasic(context.Background(), action, map[string]any{"passphrase": "test"}, p, nil)
		if err != nil || result["target"] != p.Target || !strings.Contains(result["message"].(string), "Refresh the device list") {
			t.Fatalf("unexpected completion: %v, %v", result, err)
		}
	}
}

func TestLUKSCreationRequiresUnambiguousBlankSignature(t *testing.T) {
	for _, tc := range []struct {
		response string
		accepted bool
	}{
		{`echo '{"signatures":[]}'`, true},
		{`echo '{"signatures":[{"type":"gpt","offset":"0x200"}]}'`, false},
		{`echo '{"signatures":null}'`, false}, {`echo '{}'`, false},
		{`echo '{"signatures":"unknown"}'`, false}, {`echo '{"signatures":[]} invalid'`, false},
		{`echo '{"signatures":[]}'; exit 2`, false}, {"exit 1", false}, {"exit 0", false},
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "wipefs"), []byte("#!/bin/sh\n"+tc.response+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
		if err := checkBlank(context.Background(), "/dev/loop0"); (err == nil) != tc.accepted {
			t.Fatalf("%s: got %v", tc.response, err)
		}
	}
}

func TestPasswordLimitsCountCharacters(t *testing.T) {
	for _, tc := range []struct {
		input    any
		accepted bool
	}{{nil, false}, {4, false}, {"", false}, {"a\x00b", false}, {strings.Repeat("ё", 4096), true}, {strings.Repeat("ё", 4097), false}} {
		if _, err := passphrase(map[string]any{"passphrase": tc.input}, "passphrase"); (err == nil) != tc.accepted {
			t.Fatal("unexpected password validation result")
		}
	}
}
