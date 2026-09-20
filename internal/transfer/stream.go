package transfer

import (
	"io"
	"net/http"
	"strconv"
)

// Hold the final chunk until the producer confirms success, so a failed helper
// cannot complete an otherwise correctly sized HTTP response.
func Stream(w http.ResponseWriter, r io.Reader, size int64, finish func() error) {
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	tail := min(size, int64(32*1024))
	if _, err := io.CopyN(w, r, size-tail); err != nil {
		panic(http.ErrAbortHandler)
	}
	last, err := io.ReadAll(io.LimitReader(r, tail+1))
	if err != nil || int64(len(last)) != tail {
		panic(http.ErrAbortHandler)
	}
	if err := finish(); err != nil {
		panic(http.ErrAbortHandler)
	}
	if _, err := w.Write(last); err != nil {
		panic(http.ErrAbortHandler)
	}
}
