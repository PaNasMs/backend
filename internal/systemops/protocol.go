// Package systemops holds the Go implementation of the privileged system
// operation helper. It reproduces the wire contract currently served by the
// Python management layer (backend/management/main.py and its helpers): the
// query/plan/execute/recover modes, JSON on stdin, a bounded JSON result on
// stdout, newline-delimited progress/cancellation messages on stderr, and a
// cooperative cancellation pipe on file descriptor 3.
//
// These primitives are standalone and host-independent so they can be tested
// without privileged access. They are not wired into production routing yet;
// GO-02 owns dispatch and the incremental Go/legacy routing table.
package systemops

// Wire limits, kept identical to the current Go manager
// (internal/management/manager.go) so the helper stays a drop-in on the same
// protocol:
//   - the manager caps request bodies at 1 MiB before invoking the helper;
//   - it reads at most 4 MiB of result JSON, treating overflow as an error;
//   - it reads stderr progress lines up to 1 MiB each and ignores stages of
//     512 bytes or longer.
const (
	// MaxInput is the largest JSON request the helper accepts on stdin.
	MaxInput = 1 << 20
	// MaxOutput is the largest JSON result the helper writes to stdout.
	MaxOutput = 4 << 20
	// MaxProgressLine is the largest single stderr progress line.
	MaxProgressLine = 1 << 20
	// MaxStage is the exclusive upper bound on a progress stage string; the
	// manager drops stages that are this long or longer.
	MaxStage = 512
)

// Mode is one of the four operation modes carried as the helper's first
// argument. Any other value is rejected before execution.
type Mode string

const (
	ModeQuery   Mode = "query"
	ModePlan    Mode = "plan"
	ModeExecute Mode = "execute"
	ModeRecover Mode = "recover"
)

// ValidMode reports whether s names one of the four accepted modes.
func ValidMode(s string) bool {
	switch Mode(s) {
	case ModeQuery, ModePlan, ModeExecute, ModeRecover:
		return true
	}
	return false
}

// Result is the common shape the manager decodes from a helper's stdout. The
// helper always emits valid JSON; these fields carry the outcome the manager
// journals. Absent fields keep their zero value, matching the Python contract
// where a bare result implies success with changes applied.
//
//   - Error: a redacted, human-readable failure message; the job is marked
//     failed with this as its stage.
//   - Cancelled: the operation stopped at a declared safe point having left a
//     recoverable state; never set for an uncertain failure.
//   - NoChanges: proof that no mutation began. Only then may a failed job be
//     auto-acknowledged. An uncertain failure must leave this false.
type Result struct {
	Error     string `json:"error,omitempty"`
	Cancelled bool   `json:"cancelled,omitempty"`
	NoChanges bool   `json:"noChanges,omitempty"`
}
