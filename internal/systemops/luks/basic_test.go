package luks

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestBasicOpenRedactsWrongKeyAndBusyErrors(t *testing.T) {
	for _, tc := range []struct{ code, want string }{{"2", "password"}, {"5", "busy"}} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "cryptsetup"), []byte("#!/bin/sh\ncat >&2\nexit "+tc.code+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
		_, err := applyBasic(context.Background(), "luks.open", map[string]any{"passphrase": "secret marker"}, &prepared{}, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "secret marker") {
			t.Fatalf("unexpected failure: %v", err)
		}
	}
}

func TestLUKSCreationRequiresUnambiguousBlankSignature(t *testing.T) {
	for _, tc := range []struct {
		response string
		accepted bool
	}{
		{"exit 2", true}, {"echo TYPE=ext4", false}, {"echo PTTYPE=gpt", false}, {"exit 8", false}, {"exit 1", false},
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "blkid"), []byte("#!/bin/sh\n"+tc.response+"\n"), 0700); err != nil {
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
