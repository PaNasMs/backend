package systemops

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// reporterWithPipe builds a Reporter whose control descriptor is the read end
// of a fresh pipe, returning the write end for the test to drive.
func reporterWithPipe(t *testing.T, progress *bytes.Buffer) (*Reporter, *os.File) {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	env := func(key string) string {
		if key == ControlFDEnv {
			return strconv.Itoa(int(read.Fd()))
		}
		return ""
	}
	r := NewReporter(progress, env)
	t.Cleanup(func() { r.Close(); write.Close() })
	// NewReporter reopened the fd as its own *os.File; the original read end can
	// be closed by the test's pipe pair going out of scope, but keep it simple:
	// hand back the write end for signalling.
	_ = read
	return r, write
}

func TestReporterEmitsStageAndCancellable(t *testing.T) {
	var buf bytes.Buffer
	r := NewReporter(&buf, func(string) string { return "" })
	r.Stage("Creating file system")
	r.Cancellable(true)
	r.Stage(strings.Repeat("x", MaxStage)) // dropped: too long
	r.Stage("")                            // dropped: empty

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), buf.String())
	}
	var first struct {
		Stage string `json:"stage"`
	}
	if json.Unmarshal([]byte(lines[0]), &first) != nil || first.Stage != "Creating file system" {
		t.Errorf("first line = %q", lines[0])
	}
	var second struct {
		Cancellable *bool `json:"cancellable"`
	}
	if json.Unmarshal([]byte(lines[1]), &second) != nil || second.Cancellable == nil || !*second.Cancellable {
		t.Errorf("second line = %q", lines[1])
	}
}

func TestCheckpointNoPipeIsNoop(t *testing.T) {
	r := NewReporter(&bytes.Buffer{}, func(string) string { return "" })
	if err := r.Checkpoint(); err != nil {
		t.Errorf("no-pipe checkpoint returned %v", err)
	}
}

func TestCheckpointPendingByteCancels(t *testing.T) {
	var buf bytes.Buffer
	r, write := reporterWithPipe(t, &buf)
	// No request yet.
	if err := r.Checkpoint(); err != nil {
		t.Fatalf("premature cancel: %v", err)
	}
	if _, err := write.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := r.Checkpoint(); err != ErrCancelled {
		t.Fatalf("after byte: got %v, want ErrCancelled", err)
	}
	// Cancellation must have announced non-cancellability.
	if !strings.Contains(buf.String(), `"cancellable":false`) {
		t.Errorf("cancel did not emit cancellable=false: %q", buf.String())
	}
}

func TestCheckpointEOFCancels(t *testing.T) {
	var buf bytes.Buffer
	r, write := reporterWithPipe(t, &buf)
	if err := r.Checkpoint(); err != nil {
		t.Fatalf("premature cancel: %v", err)
	}
	// Manager closing the write end is a cancel request (EOF).
	write.Close()
	if err := r.Checkpoint(); err != ErrCancelled {
		t.Fatalf("after EOF: got %v, want ErrCancelled", err)
	}
}
