package systemops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// DefaultTimeout is the per-command timeout the Python common.command uses.
const DefaultTimeout = 120 * time.Second

// stageForCommand maps a command basename to the human-readable progress stage
// the Python common.command emits when PANASMS_OPERATION=1. Kept identical so
// the UI shows the same wording.
var stageForCommand = map[string]string{
	"mdadm":            "Modifying array",
	"mkfs.ext4":        "Creating file system",
	"mkfs.xfs":         "Creating file system",
	"mkfs.btrfs":       "Creating file system",
	"mkfs.vfat":        "Creating file system",
	"sfdisk":           "Modifying partition",
	"parted":           "Modifying partition table",
	"e2fsck":           "Checking file system",
	"resize2fs":        "Resizing file system",
	"btrfs":            "Modifying file system",
	"xfs_growfs":       "Growing file system",
	"mount":            "Mounting volume",
	"umount":           "Unmounting volume",
	"cryptsetup":       "Processing encrypted volume",
	"rsync":            "Copying and verifying home folders",
	"useradd":          "Creating user",
	"usermod":          "Updating user",
	"userdel":          "Deleting user",
	"chpasswd":         "Change password",
	"apt-get":          "Updating packages",
	"systemctl":        "Applying service state",
	"update-initramfs": "Updating boot configuration",
	"udevadm":          "Checking device state",
	"smartctl":         "Submitting SMART test command",
}

// CommandStage returns the progress stage the Python layer would announce for
// the given command basename, defaulting to "Applying changes".
func CommandStage(name string) string {
	if s, ok := stageForCommand[filepath.Base(name)]; ok {
		return s
	}
	return "Applying changes"
}

// CommandOptions tune a single Command invocation.
type CommandOptions struct {
	// Input is written to the command's stdin.
	Input []byte
	// Accepted lists exit codes treated as success. Empty means {0}.
	Accepted []int
	// Timeout overrides DefaultTimeout when non-zero.
	Timeout time.Duration
	// Reporter, when set and Operation is true, receives the per-command stage
	// before the command runs, matching PANASMS_OPERATION=1 behavior.
	Reporter  *Reporter
	Operation bool
}

// Command runs an argument-vector subprocess and returns its stdout. It
// reproduces backend/management/common.command: a fixed environment of
// LC_ALL=C and DEBIAN_FRONTEND=noninteractive, a bounded timeout, and a
// redacted error that never leaks the command's output. Never build the argv
// from a shell string; pass args as separate elements.
func Command(ctx context.Context, args []string, opts CommandOptions) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New("systemops: empty command")
	}
	accepted := opts.Accepted
	if len(accepted) == 0 {
		accepted = []int{0}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if opts.Operation && opts.Reporter != nil {
		opts.Reporter.Stage(CommandStage(args[0]))
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Once a mutation starts, cancellation must wait for a domain safe point.
	// Killing apt/dpkg or a formatter on a request deadline can corrupt state.
	runCtx := ctx
	cancel := func() {}
	if opts.Operation {
		runCtx = context.WithoutCancel(ctx)
	} else {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	cmd := exec.CommandContext(runCtx, args[0], args[1:]...)
	cmd.Env = commandEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	if opts.Input != nil {
		cmd.Stdin = bytes.NewReader(opts.Input)
	}
	stdout := boundedBuffer{limit: MaxOutput}
	cmd.Stdout = &stdout
	cmd.Stderr = nil // discard: never surface raw command output

	err := cmd.Run()
	if stdout.overflow {
		return nil, reject("Command output too large; check the operation result")
	}
	if err == nil {
		err = &exec.ExitError{ProcessState: cmd.ProcessState}
	}
	// A killed process reports an ExitError with a signal (code -1); classify
	// the timeout first so it is not mistaken for an ordinary non-zero exit.
	if runCtx.Err() == context.DeadlineExceeded {
		return nil, reject(fmt.Sprintf("Command %s timed out", filepath.Base(args[0])))
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code := exit.ExitCode()
		for _, ok := range accepted {
			if code == ok {
				return stdout.Bytes(), nil
			}
		}
		return nil, reject(fmt.Sprintf(
			"Command %s exited with code %d. Check the object's state and system journal.",
			filepath.Base(args[0]), code))
	}
	return nil, reject(fmt.Sprintf("Command %s could not run", filepath.Base(args[0])))
}

func commandEnv() []string {
	// A fixed environment matching common.command; the parent environment is
	// intentionally not inherited wholesale for the locale-sensitive vars.
	return append(baseEnv(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
}

// Copying runs a staging-copy command whose caller owns rollback. It announces
// cancellability, polls the control pipe every 250ms, and on cancellation (or
// timeout/failure) terminates the whole child process group, escalating from
// SIGTERM to SIGKILL. It mirrors backend/management/job_control.copying.
//
// The command is started in its own session/process group so a cancel reaps
// every descendant, not just the immediate child.
func Copying(ctx context.Context, r *Reporter, args []string, timeout time.Duration) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New("systemops: empty command")
	}
	if timeout == 0 {
		timeout = 86400 * time.Second
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, reject("Copy reporter is required")
	}
	if err := r.Checkpoint(); err != nil {
		return nil, err
	}
	r.Cancellable(true)
	defer r.Cancellable(false)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(baseEnv(), "LC_ALL=C")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout := boundedBuffer{limit: MaxOutput}
	cmd.Stdout = &stdout
	if err := cmd.Start(); err != nil {
		return nil, reject(fmt.Sprintf("Command %s could not run", filepath.Base(args[0])))
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.After(timeout)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case err := <-done:
			if err != nil {
				return nil, reject("Copy command failed")
			}
			if stdout.overflow {
				return nil, reject("Copy output too large")
			}
			return stdout.Bytes(), nil
		case <-ticker.C:
			if r.Checkpoint() != nil {
				killGroup(cmd, done)
				return nil, ErrCancelled
			}
		case <-deadline:
			killGroup(cmd, done)
			return nil, reject("Copy command timed out")
		case <-ctx.Done():
			killGroup(cmd, done)
			return nil, ctx.Err()
		}
	}
}

// Continue draining after the limit: a verbose command must not exhaust memory
// or receive SIGPIPE halfway through a mutation.
type boundedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.buf.Len()
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	_, _ = b.buf.Write(p)
	return n, nil
}

func (b *boundedBuffer) Bytes() []byte { return b.buf.Bytes() }
