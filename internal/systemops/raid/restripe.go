package raid

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"syscall"
)

// exportRAID6 reads stopped, role-ordered members during conversion to
// the corresponding Linux MD RAID6 layout with dedicated last Q.
// Members are section readers beginning at the unchanged data offset. The caller
// must discard an incomplete destination on error. Never write to the members.
func exportRAID6(ctx context.Context, members []io.ReaderAt, chunk int, size int64, layout int, dst io.Writer) error {
	n := len(members)
	if n < 4 || n > 256 || chunk < 4096 || chunk > 1<<24 || chunk&(chunk-1) != 0 || int64(chunk)*int64(n) > 128<<20 {
		return errors.New("unsupported RAID6 recovery geometry")
	}
	stripeBytes := int64(n-2) * int64(chunk)
	if size <= 0 || size%stripeBytes != 0 {
		return errors.New("incomplete RAID6 stripe")
	}
	row := make([][]byte, n)
	for i := range row {
		row[i] = make([]byte, chunk)
	}
	for stripe := int64(0); stripe < size/stripeBytes; stripe++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		for i, member := range members {
			read, err := member.ReadAt(row[i], stripe*int64(chunk))
			if err != nil {
				return fmt.Errorf("stripe %d member %d: %w", stripe, i, err)
			}
			if read != chunk {
				return io.ErrUnexpectedEOF
			}
		}
		oldP, oldQ, oldSlots := stripeRoles(n, stripe, layout, false)
		newP, newQ, newSlots := stripeRoles(n, stripe, layout, true)
		oldOK := matchesSyndromes(row, oldP, oldQ)
		newOK := matchesSyndromes(row, newP, newQ)
		if !oldOK && !newOK {
			return fmt.Errorf("stripe %d has no valid RAID6 layout", stripe)
		}
		for block := 0; block < n-2; block++ {
			oldData := row[oldSlots[block]]
			newData := row[newSlots[block]]
			if oldOK && newOK && !bytes.Equal(oldData, newData) {
				return fmt.Errorf("stripe %d has ambiguous RAID6 data", stripe)
			}
			data := oldData
			if newOK {
				data = newData
			}
			written, err := dst.Write(data)
			if err != nil {
				return err
			}
			if written != len(data) {
				return io.ErrShortWrite
			}
		}
	}
	return nil
}

// Linux MD layouts 0..3 rotate parity left/right. Symmetric layouts rotate
// data with parity; asymmetric layouts enumerate surviving slots in order.
func stripeRoles(n int, stripe int64, layout int, dedicated bool) (int, int, []int) {
	width := n
	if dedicated {
		width--
	}
	p := int(stripe % int64(width))
	if layout == 0 || layout == 2 {
		p = width - 1 - p
	}
	q := (p + 1) % n
	if dedicated {
		q = n - 1
	}
	if layout == 4 {
		p = 0
		if !dedicated {
			q = 1
		}
	}
	start := 0
	if layout == 2 || layout == 3 {
		start = (q + 1) % n
		if dedicated {
			start = (p + 1) % width
		}
	}
	slots := make([]int, 0, n-2)
	for i := 0; i < n; i++ {
		slot := (start + i) % n
		if slot != q && slot != p {
			slots = append(slots, slot)
		}
	}
	return p, q, slots
}

// Linux MD orders Q coefficients by physical slot, starting after the Q slot
// and skipping P. Multiplication by two uses the RAID6 field polynomial 0x11d.
func matchesSyndromes(row [][]byte, p, q int) bool {
	for i := range row[p] {
		var parity, syndrome byte
		for step := len(row) - 1; step > 0; step-- {
			slot := (q + step) % len(row)
			if slot == p {
				continue
			}
			value := row[slot][i]
			parity ^= value
			if syndrome&0x80 != 0 {
				syndrome = syndrome<<1 ^ 0x1d
			} else {
				syndrome <<= 1
			}
			syndrome ^= value
		}
		if parity != row[p][i] || syndrome != row[q][i] {
			return false
		}
	}
	return true
}

// ExportDowngrade writes a recovered logical image to dst. Accept only
// offline regular-file copies, so live kernel writes cannot race the export.
func ExportDowngrade(ctx context.Context, paths []string, dst io.Writer) error {
	if len(paths) < 4 || len(paths) > 256 {
		return errors.New("provide all active member images")
	}
	members := make([]io.ReaderAt, len(paths))
	var common []byte
	var events uint64
	var chunk int
	var size int64
	for _, path := range paths {
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), path)
		defer f.Close()
		stat, err := f.Stat()
		if err != nil {
			return err
		}
		if !stat.Mode().IsRegular() {
			return errors.New("expected offline regular-file member images")
		}
		super := make([]byte, 4096)
		if _, err := f.ReadAt(super, 4096); err != nil {
			return err
		}
		u32, u64 := binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
		maxDev, dev := u32(super[220:]), u32(super[160:])
		if maxDev > (4096-256)/2 || dev >= maxDev {
			return errors.New("invalid MD role table")
		}
		saved := u32(super[216:])
		clear(super[216:220])
		var sum uint64
		limit := 256 + int(maxDev)*2
		for i := 0; i < limit; i += 4 {
			if i+4 > limit {
				sum += uint64(binary.LittleEndian.Uint16(super[i:]))
			} else {
				sum += uint64(u32(super[i:]))
			}
		}
		if uint32(sum)+uint32(sum>>32) != saved || u32(super) != 0xa92b4efc || u32(super[4:]) != 1 || u64(super[144:]) != 8 {
			return errors.New("invalid MD 1.2 member metadata")
		}
		if u32(super[8:])&^1 != 4 || u32(super[72:]) != 6 || u32(super[76:]) > 4 || u32(super[92:]) != uint32(len(paths)) || u32(super[100:]) != 5 || u32(super[112:]) != 0 || u32(super[116:]) != u32(super[76:])+16 || u32(super[120:]) != u32(super[88:]) || u32(super[124:]) != 0 {
			return errors.New("unsupported interrupted RAID6 downgrade")
		}
		if common == nil {
			common = super
			events = u64(super[200:])
		} else if !bytes.Equal(common[16:128], super[16:128]) || events != u64(super[200:]) || !bytes.Equal(common[220:224], super[220:224]) || !bytes.Equal(common[256:limit], super[256:limit]) {
			return errors.New("member images disagree on array identity, geometry or generation")
		}
		role := binary.LittleEndian.Uint16(super[256+dev*2:])
		if int(role) >= len(paths) || members[role] != nil {
			return errors.New("missing or duplicate RAID role")
		}
		offset, sectors := u64(super[128:]), u64(super[80:])
		available := uint64(stat.Size() / 512)
		if offset < 16 || offset > available || sectors == 0 || sectors > available-offset || sectors > uint64(math.MaxInt64/512)/uint64(len(paths)-2) || sectors > u64(super[136:]) {
			return errors.New("member geometry exceeds image size")
		}
		chunk = int(u32(super[88:])) * 512
		size = int64(sectors) * 512 * int64(len(paths)-2)
		members[role] = io.NewSectionReader(f, int64(offset)*512, int64(sectors)*512)
	}
	return exportRAID6(ctx, members, chunk, size, int(binary.LittleEndian.Uint32(common[76:])), dst)
}
