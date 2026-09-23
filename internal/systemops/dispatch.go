package systemops

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// Request is the JSON the helper reads on stdin for plan/execute modes. Query
// carries {view,target}; recover carries {action,params}. Params keeps
// json.Number so fingerprints stay precise (see Decode).
type Actor struct {
	UID       int    `json:"uid"`
	Epoch     string `json:"epoch"`
	Principal string `json:"principal"`
}
type Request struct {
	Actor        *Actor         `json:"actor,omitempty"`
	Action       string         `json:"action"`
	Params       map[string]any `json:"params"`
	View         string         `json:"view,omitempty"`
	Target       string         `json:"target,omitempty"`
	Fingerprint  string         `json:"fingerprint,omitempty"`
	Confirmation string         `json:"confirmation,omitempty"`
	ID           string         `json:"id,omitempty"`
}

// Handler runs one authorized domain operation in the isolated helper.
type Handler func(mode Mode, user string, req *Request, r *Reporter) (json.RawMessage, error)

// ErrNoRoute is returned when no handler is registered for a mode/action. It is
// deliberately explicit: there is no runtime fallback to the legacy Python
// implementation (plan §3.3).
var ErrNoRoute = errors.New("no Go handler is registered for this operation")

// ReadRequest reads and decodes a bounded request from r, enforcing MaxInput.
// It uses json.Number decoding so downstream fingerprints keep integer
// precision, and rejects trailing garbage after the JSON value.
func ReadRequest(r io.Reader) (*Request, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxInput {
		return nil, reject("Request too large")
	}
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, reject("Invalid request")
	}
	var req Request
	if err := Decode(data, &req); err != nil {
		return nil, reject("Invalid request")
	}
	return &req, nil
}

// WriteResult marshals v and writes it to w, enforcing MaxOutput. On overflow
// it returns an error rather than emitting truncated, invalid JSON.
func WriteResult(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > MaxOutput {
		return reject("Handler response too large")
	}
	_, err = w.Write(data)
	return err
}

// Run is the helper entry point: it reads a request from in, runs the handler,
// and writes the result to out with progress/cancellation on the reporter. A
// validation rejection or a missing route is reported as a {"error": ...}
// result (exit 0, valid JSON) so the manager journals a clean failure; an I/O
// framing failure returns a non-nil error for the caller to exit non-zero.
func Run(mode Mode, user string, in io.Reader, out io.Writer, r *Reporter, h Handler) error {
	if !ValidMode(string(mode)) {
		return WriteResult(out, Result{Error: "Unknown operation mode", NoChanges: true})
	}
	req, err := ReadRequest(in)
	if err != nil {
		return WriteResult(out, Result{Error: messageFor(err), NoChanges: true})
	}
	if h == nil {
		return WriteResult(out, Result{Error: ErrNoRoute.Error(), NoChanges: true})
	}
	result, err := h(mode, user, req, r)
	if err != nil {
		if errors.Is(err, ErrCancelled) {
			return WriteResult(out, Result{Cancelled: true})
		}
		return WriteResult(out, Result{Error: messageFor(err), NoChanges: Unchanged(err)})
	}
	return WriteResult(out, json.RawMessage(result))
}

// messageFor returns a caller-safe message: validation rejections carry their
// own wording; anything else is redacted to a generic handler error so raw
// internals never reach the client.
func messageFor(err error) string {
	if IsRejected(err) {
		return err.Error()
	}
	return "System handler error"
}

// Env is the process environment accessor, indirected so tests can inject one.
var Env = os.Getenv

type unchangedError struct{ error }

func (e unchangedError) Unwrap() error { return e.error }
func BeforeMutation(err error) error   { return unchangedError{err} }
func Unchanged(err error) bool         { var e unchangedError; return errors.As(err, &e) }
