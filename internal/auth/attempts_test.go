package auth

import (
	"fmt"
	"testing"
	"time"
)

func TestAttemptLimiterIsBoundedAndExpires(t *testing.T) {
	var l AttemptLimiter
	now := time.Now()
	for i := 0; i < 10; i++ {
		if !l.Permit("alice", now) {
			t.Fatal("early rejection")
		}
	}
	if l.Permit("alice", now) {
		t.Fatal("limit bypassed")
	}
	if !l.Permit("bob", now) {
		t.Fatal("other user blocked")
	}
	for i := 0; i < 1100; i++ {
		if !l.Permit(fmt.Sprint(i), now.Add(time.Second)) {
			t.Fatal("global lockout")
		}
	}
	if len(l.windows) > 1024 {
		t.Fatal("unbounded limiter")
	}
	if !l.Permit("alice", now.Add(time.Minute)) {
		t.Fatal("expired window retained")
	}
}
