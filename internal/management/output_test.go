package management

import (
	"bytes"
	"io"
	"testing"
)

func TestOversizedHelperOutputIsDrainedAndBounded(t *testing.T) {
	b := limitedOutput{limit: 10}
	n, err := io.Copy(&b, bytes.NewReader(bytes.Repeat([]byte("x"), 10000)))
	if err != nil || n != 10000 || b.Len() != 10 || !b.overflow {
		t.Fatal(n, err, b.Len(), b.overflow)
	}
	if n, err := b.Write([]byte("more")); err != nil || n != 4 || b.Len() != 10 {
		t.Fatal(n, err, b.Len())
	}
}
