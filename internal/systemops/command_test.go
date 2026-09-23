package systemops

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCommandReturnsStdout(t *testing.T) {
	out, err := Command(context.Background(), []string{"printf", "hello"}, CommandOptions{})
	if err != nil {
		t.Fatalf("printf: %v", err)
	}
	if string(out) != "hello" {
		t.Errorf("stdout = %q, want hello", out)
	}
}

func TestCommandNonzeroIsRejectedAndRedacted(t *testing.T) {
	// `false` exits 1; the error must not carry stdout/stderr, only a code.
	_, err := Command(context.Background(), []string{"false"}, CommandOptions{})
	if !IsRejected(err) {
		t.Fatalf("false: got %v, want rejection", err)
	}
	if !strings.Contains(err.Error(), "code 1") {
		t.Errorf("error should name the exit code: %q", err)
	}
}

func TestCommandAcceptedCodes(t *testing.T) {
	out, err := Command(context.Background(), []string{"false"}, CommandOptions{Accepted: []int{1}})
	if err != nil {
		t.Fatalf("accepted code 1 still failed: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("unexpected stdout: %q", out)
	}
}

func TestCommandTimeoutIsRejected(t *testing.T) {
	_, err := Command(context.Background(), []string{"sleep", "5"}, CommandOptions{Timeout: 100 * time.Millisecond})
	if !IsRejected(err) {
		t.Fatalf("timeout: got %v, want rejection", err)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error should mention timeout: %q", err)
	}
}

func TestCommandStdinIsPiped(t *testing.T) {
	out, err := Command(context.Background(), []string{"cat"}, CommandOptions{Input: []byte("piped")})
	if err != nil {
		t.Fatalf("cat: %v", err)
	}
	if string(out) != "piped" {
		t.Errorf("stdout = %q, want piped", out)
	}
}

func TestCommandStageAnnouncedWhenOperation(t *testing.T) {
	var buf logBuf
	r := NewReporter(&buf, func(string) string { return "" })
	if _, err := Command(context.Background(), []string{"true"}, CommandOptions{Operation: true, Reporter: r}); err != nil {
		t.Fatalf("true: %v", err)
	}
	if !strings.Contains(buf.String(), CommandStage("true")) {
		t.Errorf("stage not announced: %q", buf.String())
	}
}

func TestCopyingSucceeds(t *testing.T) {
	var buf logBuf
	r := NewReporter(&buf, func(string) string { return "" })
	out, err := Copying(context.Background(), r, []string{"printf", "done"}, 5*time.Second)
	if err != nil {
		t.Fatalf("copying: %v", err)
	}
	if string(out) != "done" {
		t.Errorf("stdout = %q, want done", out)
	}
}

// TestCopyingCancelReapsProcessGroup starts a long sleep, signals cancel via the
// control pipe, and asserts the whole process group is gone afterwards.
func TestCopyingCancelReapsProcessGroup(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	env := func(key string) string {
		if key == ControlFDEnv {
			return strconv.Itoa(int(read.Fd()))
		}
		return ""
	}
	var buf logBuf
	r := NewReporter(&buf, env)
	defer r.Close()

	// Cancel shortly after the copy starts.
	go func() {
		time.Sleep(300 * time.Millisecond)
		write.Write([]byte{1})
	}()

	start := time.Now()
	// A shell that spawns a child sleep, so the process group has >1 member.
	_, err = Copying(context.Background(), r, []string{"sh", "-c", "sleep 30 & wait"}, 30*time.Second)
	if err != ErrCancelled {
		t.Fatalf("copying cancel: got %v, want ErrCancelled", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("cancel took %v; SIGTERM should have reaped promptly", elapsed)
	}
}

func TestKillGroupEscalation(t *testing.T) {
	// A process that ignores SIGTERM must still be reaped via SIGKILL.
	if _, err := lookPathSh(); err != nil {
		t.Skip("sh unavailable")
	}
	read, write, _ := os.Pipe()
	defer read.Close()
	defer write.Close()
	env := func(key string) string {
		if key == ControlFDEnv {
			return strconv.Itoa(int(read.Fd()))
		}
		return ""
	}
	var buf logBuf
	r := NewReporter(&buf, env)
	defer r.Close()

	go func() {
		time.Sleep(300 * time.Millisecond)
		write.Close() // EOF cancel
	}()

	// trap '' TERM makes SIGTERM a no-op; killGroup must escalate to SIGKILL
	// after its grace period.
	start := time.Now()
	_, err := Copying(context.Background(), r, []string{"sh", "-c", "trap '' TERM; sleep 30"}, 30*time.Second)
	if err != ErrCancelled {
		t.Fatalf("got %v, want ErrCancelled", err)
	}
	if elapsed := time.Since(start); elapsed < 5*time.Second {
		t.Errorf("SIGKILL escalation returned in %v; expected ~5s grace", elapsed)
	}
}

func lookPathSh() (string, error) { return "/bin/sh", nil }

// logBuf is a tiny concurrency-safe buffer: Copying writes progress from the
// main goroutine only, but the compiler needs a concrete io.Writer.
type logBuf struct{ b strings.Builder }

func (l *logBuf) Write(p []byte) (int, error) { return l.b.Write(p) }
func (l *logBuf) String() string              { return l.b.String() }
