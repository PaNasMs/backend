package systemops

import (
	"errors"
	"path"
	"regexp"
	"strings"
)

// Rejected is returned by validation helpers when input fails a contract
// check. It mirrors the Python `Rejected` exception raised by common.require:
// a caller-facing, non-sensitive message that becomes the operation's error.
type Rejected struct{ Message string }

func (e *Rejected) Error() string { return e.Message }

func reject(message string) error { return &Rejected{Message: message} }

// IsRejected reports whether err is a validation rejection.
func IsRejected(err error) bool {
	var r *Rejected
	return errors.As(err, &r)
}

// namePattern matches the Python common.name contract exactly: a lowercase
// letter or underscore, then up to 30 more lowercase letters, digits,
// underscores or hyphens.
var namePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)

// Name validates an identifier (user, group, interface, ...) against the same
// rule the Python layer enforces, returning it unchanged when valid.
func Name(value string) (string, error) {
	if !namePattern.MatchString(value) {
		return "", reject("Invalid name")
	}
	return value, nil
}

// Integer validates that value is within [low, high] inclusive. The Python
// contract explicitly rejects booleans; Go's type system already separates
// bool from the integer types, so any int64 here is genuinely numeric.
func Integer(value, low, high int64) (int64, error) {
	if value < low || value > high {
		return 0, reject("Number outside the allowed range")
	}
	return value, nil
}

// CleanPath validates an absolute, normalized path, matching common.clean_path:
// it must start with "/", be shorter than 1024 bytes, contain no control
// characters, already be in normalized form and contain no ".." component.
// It returns the cleaned path (identical to the input when valid).
func CleanPath(value string) (string, error) {
	if !strings.HasPrefix(value, "/") || len(value) >= 1024 {
		return "", reject("Invalid path")
	}
	for _, c := range value {
		if c < 32 {
			return "", reject("Invalid path")
		}
	}
	// path.Clean collapses "." , duplicate slashes and trailing slashes and
	// resolves ".." lexically. Requiring the input to already equal its clean
	// form is how the Python side ensures the path was normalized by the
	// caller rather than silently rewritten here.
	if path.Clean(value) != value {
		return "", reject("The path must be absolute and normalized")
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return "", reject("The path must be absolute and normalized")
		}
	}
	return value, nil
}
