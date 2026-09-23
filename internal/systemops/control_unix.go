package systemops

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func parseFD(v string) (int, error) {
	fd, err := strconv.Atoi(v)
	if err != nil || fd < 0 {
		return 0, reject("Invalid control descriptor")
	}
	return fd, nil
}

// readNonBlocking polls f for a pending byte without blocking. It returns
// (requested, closed, err): requested is true if a byte was read, closed is
// true on EOF (the manager closed the write end), and a would-block condition
// returns all-false with no error. This mirrors job_control.checkpoint, which
// sets the fd non-blocking and treats both a byte and EOF as a cancel request.
func readNonBlocking(f *os.File) (requested bool, closed bool, err error) {
	fd := int(f.Fd())
	// Set non-blocking so a read on an empty pipe returns EAGAIN instead of
	// stalling the operation.
	if err := unix.SetNonblock(fd, true); err != nil {
		return false, false, err
	}
	buf := make([]byte, 1)
	n, err := unix.Read(fd, buf)
	switch {
	case n > 0:
		return true, false, nil
	case n == 0 && err == nil:
		return false, true, nil // EOF: write end closed
	case err == unix.EAGAIN || err == unix.EWOULDBLOCK:
		return false, false, nil
	default:
		return false, false, err
	}
}
