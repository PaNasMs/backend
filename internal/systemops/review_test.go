package systemops

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDecodeRejectsTrailingData(t *testing.T) {
	for _, input := range []string{`{} {}`, `{} garbage`, `{} null`, `null`, `[]`} {
		if _, err := ReadRequest(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
	var v any
	if err := Decode([]byte("{} \n\t"), &v); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalNumericParityWithPython(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python fixture oracle unavailable")
	}
	for _, input := range []string{"-0", "-0.0", "1.0", "1e0", "1e-5", "1e-4", "1e6", "1e15", "1e16", "1.2345678901234567", "18446744073709551615"} {
		var value any
		if err := Decode([]byte(input), &value); err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		if err := canonical(&got, value); err != nil {
			t.Fatal(err)
		}
		want, err := exec.Command(python, "-c", "import json,sys; print(json.dumps(json.loads(sys.argv[1]), separators=(',',':')),end='')", input).Output()
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != string(want) {
			t.Errorf("%s: got %s want %s", input, &got, want)
		}
	}
}

func TestCommandRejectsUnacceptedSuccess(t *testing.T) {
	if _, err := Command(context.Background(), []string{"true"}, CommandOptions{Accepted: []int{1}}); !IsRejected(err) {
		t.Fatalf("accepted code 0: %v", err)
	}
}

func TestCommandBoundsOutputWithoutInterruptingMutation(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "finished")
	_, err := Command(context.Background(), []string{"sh", "-c", `head -c 5000000 /dev/zero; printf done > "$1"`, "sh", marker}, CommandOptions{Operation: true})
	if !IsRejected(err) {
		t.Fatalf("overflow: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("mutation interrupted: %v", err)
	}
}

func TestCommandMutationFinishesDespiteContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	out, err := Command(ctx, []string{"sh", "-c", "sleep 0.2; printf done"}, CommandOptions{Operation: true, Timeout: time.Millisecond})
	if err != nil || string(out) != "done" {
		t.Fatalf("mutation killed: %q %v", out, err)
	}
}

func TestKillGroupCleansChildAfterLeaderExits(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "pid")
	cmd := exec.Command("sh", "-c", `sh -c 'trap "" TERM; echo $$ > "$1"; exec sleep 30' sh "$1" </dev/null >/dev/null 2>&1 & wait`, "sh", pidfile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var child int
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		raw, _ := os.ReadFile(pidfile)
		child, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		if child > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if child == 0 {
		t.Fatal("child did not start")
	}
	killGroup(cmd, done)
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(child) + "/stat")
		if os.IsNotExist(err) || strings.Contains(string(raw), ") Z ") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("descendant survived leader exit")
}

func TestNumericFingerprintDoesNotEraseIntegerFloatDistinction(t *testing.T) {
	a, _ := Fingerprint("x", map[string]any{"n": json.Number("1")}, nil)
	b, _ := Fingerprint("x", map[string]any{"n": json.Number("1.0")}, nil)
	if a == b {
		t.Fatal("integer and float fingerprints collided")
	}
}
