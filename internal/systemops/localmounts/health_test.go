package localmounts

import (
	"context"
	"errors"
	"panasms.local/backend/internal/systemops"
	"reflect"
	"testing"
)

func TestRepairAlwaysVerifiesWithoutChanges(t *testing.T) {
	calls := [][]string{}
	operations := []bool{}
	s := &service{tool: func(string) bool { return true }, run: func(_ context.Context, args []string, opts systemops.CommandOptions) ([]byte, error) {
		calls = append(calls, args)
		operations = append(operations, opts.Operation)
		return nil, nil
	}}
	clean, reason := s.checkFilesystem(context.Background(), "/proc/123/fd/4", "ext4", true, nil)
	if !clean || reason != "" || !reflect.DeepEqual(calls, [][]string{{"e2fsck", "-p", "/proc/123/fd/4"}, {"e2fsck", "-f", "-n", "/proc/123/fd/4"}}) || !reflect.DeepEqual(operations, []bool{true, false}) {
		t.Fatalf("%v %s %v %v", clean, reason, calls, operations)
	}
}
func TestRepairFailureDoesNotProceedOrClaimClean(t *testing.T) {
	calls := 0
	s := &service{tool: func(string) bool { return true }, run: func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
		calls++
		return nil, errors.New("code 4")
	}}
	clean, reason := s.checkFilesystem(context.Background(), "/proc/123/fd/4", "vfat", true, nil)
	if clean || reason == "" || calls != 1 {
		t.Fatalf("%v %q %d", clean, reason, calls)
	}
}
