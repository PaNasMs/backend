package management

import (
	"context"
	"encoding/json"
)

// Native routes use the same mount namespace, bounded output and control pipe
// as legacy routes. There is no in-process privileged domain execution.
func nativeRun(ctx context.Context, mode, user string, body any) (json.RawMessage, error) {
	return runHelper(ctx, mode, user, body, []string{"/usr/lib/panasms/panasms-system-helper"})
}
