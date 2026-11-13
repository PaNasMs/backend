package raid

import (
	"bytes"
	"context"
	"io"
	"slices"
	"testing"
)

func TestExportInterruptedDowngrade(t *testing.T) {
	// Stripe zero in the old layout: Q,D0,D1,P. Stripe one in the new
	// layout: D1,P,D0,Q. Q coefficients follow physical order after Q.
	const chunk = 4096
	var disks [4]bytes.Buffer
	rows := [][4]byte{{1 ^ 4, 1, 2, 3}, {8, 12, 4, 8 ^ 8}}
	for _, row := range rows {
		for i, value := range row {
			disks[i].Write(bytes.Repeat([]byte{value}, chunk))
		}
	}
	read := func() []io.ReaderAt {
		var members []io.ReaderAt
		for i := range disks {
			members = append(members, bytes.NewReader(disks[i].Bytes()))
		}
		return members
	}
	var out bytes.Buffer
	var want bytes.Buffer
	for _, value := range []byte{1, 2, 4, 8} {
		want.Write(bytes.Repeat([]byte{value}, chunk))
	}
	if err := exportRAID6(context.Background(), read(), chunk, int64(want.Len()), 2, &out); err != nil || !bytes.Equal(out.Bytes(), want.Bytes()) {
		t.Fatalf("invalid recovery, bytes=%d err=%v", out.Len(), err)
	}
	disks[0].Bytes()[0] ^= 1
	if err := exportRAID6(context.Background(), read(), chunk, int64(want.Len()), 2, io.Discard); err == nil {
		t.Fatal("accepted corrupted stripe")
	}
}

func TestRAID6StripeRoles(t *testing.T) {
	// Row one of four-member Linux MD layouts. Slots follow logical block order.
	for _, c := range []struct {
		layout   int
		old, new []int
	}{
		{0, []int{0, 1}, []int{0, 2}},
		{1, []int{0, 3}, []int{0, 2}},
		{2, []int{0, 1}, []int{2, 0}},
		{3, []int{3, 0}, []int{2, 0}},
		{4, []int{2, 3}, []int{1, 2}},
	} {
		_, _, old := stripeRoles(4, 1, c.layout, false)
		_, _, newRoles := stripeRoles(4, 1, c.layout, true)
		if !slices.Equal(old, c.old) || !slices.Equal(newRoles, c.new) {
			t.Errorf("layout %d: %v -> %v", c.layout, old, newRoles)
		}
	}
}
