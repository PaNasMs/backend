package systemops

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// ControlFDEnv names the environment variable that carries the cancellation
// pipe's file descriptor number to the helper, matching the Python
// PANASMS_CONTROL_FD contract. The Go manager passes the pipe as ExtraFiles[0]
// and sets this to "3".
const ControlFDEnv = "PANASMS_CONTROL_FD"

// ErrCancelled is returned by Checkpoint when the manager has requested
// cancellation at a declared safe point. It mirrors the Python Cancelled
// exception; the helper converts it into a {"cancelled": true} result.
var ErrCancelled = errors.New("operation cancelled at a safe point")

// Reporter emits progress and cancellation-capability messages on stderr and
// reads cancellation requests from the control pipe. It reproduces the helper
// side of the protocol implemented by backend/management/{common,job_control}.
//
// A Reporter with no control pipe (the env var unset) still emits stages but
// treats the operation as non-cancellable, exactly as the Python helper does
// outside a cancellable job.
type Reporter struct {
	mu       sync.Mutex
	progress io.Writer // stderr in production
	control  *os.File  // FD named by PANASMS_CONTROL_FD, or nil
}

// NewReporter builds a Reporter writing progress to w. If the control-FD env
// var is set to a valid descriptor number, that descriptor is used as the
// cancellation pipe. The returned closer releases the control file.
func NewReporter(w io.Writer, env func(string) string) *Reporter {
	r := &Reporter{progress: w}
	if v := env(ControlFDEnv); v != "" {
		if fd, err := parseFD(v); err == nil {
			r.control = os.NewFile(uintptr(fd), "panasms-control")
		}
	}
	return r
}

// Stage emits a progress stage. Stages at or beyond MaxStage bytes are dropped
// by the manager, so the helper never bothers sending them.
func (r *Reporter) Stage(stage string) {
	if stage == "" || len(stage) >= MaxStage {
		return
	}
	r.emit(map[string]any{"stage": stage})
}

// Cancellable announces whether the operation can currently be cancelled. It is
// sent true when entering a safe-to-cancel section and false once past it,
// matching job_control.capability.
func (r *Reporter) Cancellable(allowed bool) {
	r.emit(map[string]any{"cancellable": allowed})
}

// Checkpoint returns ErrCancelled if the manager has requested cancellation.
// It is a cooperative, non-blocking poll: a pending byte or a closed pipe (EOF)
// both mean cancel. With no control pipe it is a no-op. On cancel it first
// announces that the operation is no longer cancellable, matching the Python
// checkpoint() which calls capability(False) before raising.
func (r *Reporter) Checkpoint() error {
	if r.control == nil {
		return nil
	}
	requested, closed, err := readNonBlocking(r.control)
	if err != nil {
		return nil // treat a transient read error as "no request yet"
	}
	if requested || closed {
		r.Cancellable(false)
		return ErrCancelled
	}
	return nil
}

func (r *Reporter) emit(v map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line, err := json.Marshal(v)
	if err != nil {
		return
	}
	r.progress.Write(append(line, '\n'))
}

// Close releases the control descriptor if one was opened.
func (r *Reporter) Close() error {
	if r.control != nil {
		return r.control.Close()
	}
	return nil
}

// WithCancellation bridges the reporter pipe to context-aware, pre-mutation
// work. The callback must not poll the reporter itself. The watcher is joined
// before returning so later checkpoints are the sole readers again.
func WithCancellation[T any](ctx context.Context, r *Reporter, run func(context.Context) (T, error)) (T, error) {
	if r == nil || r.control == nil {
		return run(ctx)
	}
	var zero T
	if err := r.Checkpoint(); err != nil {
		return zero, err
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
				if err := r.Checkpoint(); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	value, err := run(ctx)
	close(stop)
	<-done
	if cause := context.Cause(ctx); cause != nil {
		return zero, cause
	}
	if cancelErr := r.Checkpoint(); cancelErr != nil {
		return zero, cancelErr
	}
	return value, err
}
