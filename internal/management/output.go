package management

import "bytes"

// Keep draining output without killing a helper that may be committing changes.
type limitedOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.buffer.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.overflow = true
	}
	b.buffer.Write(p)
	return n, nil
}

func (b *limitedOutput) Bytes() []byte { return b.buffer.Bytes() }
func (b *limitedOutput) Len() int      { return b.buffer.Len() }
