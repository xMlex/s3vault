package service

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/port"
)

const (
	// rangeWindow bounds one backend request made on behalf of a reader. Large
	// enough to amortize a round trip, small enough that a client asking for a
	// few bytes does not pull a megabyte it will never use.
	rangeWindow = 256 << 10
	// rangePrefix is what Open reads first: the 128-byte S3VCTR01 header and, for
	// a native payload, its S3VLT01 header (an RSA-4096 wrapped key is well under
	// a kilobyte).
	rangePrefix = 64 << 10
)

// fetchFunc fills dst with plaintext bytes [start, start+len(dst)).
type fetchFunc func(dst []byte, start int64) error

// objectReader is an io.ReadSeeker over a remote object. It keeps one plaintext
// window and refetches only when the caller reads outside it, so ServeContent
// drives ranged reads and the backend is asked for the bytes actually used.
type objectReader struct {
	//nolint:containedctx // io.Reader has no context parameter and this reader is request-scoped.
	ctx    context.Context
	size   int64
	off    int64
	window []byte
	start  int64 // plaintext offset of window[0]
	fetch  fetchFunc
	n      int64
	err    error
	closed bool

	onClose func(n int64, err error)
}

func newObjectReader(ctx context.Context, size int64, fetch fetchFunc) *objectReader {
	return &objectReader{ctx: ctx, size: size, fetch: fetch}
}

func (r *objectReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	if r.off >= r.size {
		return 0, io.EOF
	}

	if r.off < r.start || r.off >= r.start+int64(len(r.window)) {
		if err := r.fill(); err != nil {
			r.err = err
			return 0, err
		}
	}

	i := r.off - r.start
	n := copy(p, r.window[i:])
	r.off += int64(n)
	r.n += int64(n)

	return n, nil
}

func (r *objectReader) fill() error {
	length := int64(rangeWindow)
	if rem := r.size - r.off; rem < length {
		length = rem
	}

	if length <= 0 {
		return nil
	}

	if cap(r.window) < int(length) {
		r.window = make([]byte, length)
	} else {
		r.window = r.window[:length]
	}

	if err := r.fetch(r.window, r.off); err != nil {
		return err
	}

	r.start = r.off

	return nil
}

// Seek implements io.Seeker. ServeContent uses it to learn the size and to jump
// to the start of a requested range; no backend request is made here.
func (r *objectReader) Seek(offset int64, whence int) (int64, error) {
	var abs int64

	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.off + offset
	case io.SeekEnd:
		abs = r.size + offset
	default:
		return 0, fmt.Errorf("seek: invalid whence %d", whence)
	}

	if abs < 0 {
		return 0, fmt.Errorf("seek: negative position %d", abs)
	}

	r.off = abs

	return abs, nil
}

func (r *objectReader) Close() error {
	if r.closed {
		return nil
	}

	r.closed = true
	if r.onClose != nil {
		r.onClose(r.n, r.err)
	}

	return nil
}

// plaintextFetcher reads a plaintext payload straight from the backend. base is
// the stored offset of plaintext byte 0 (0 for a containerless object, the
// container header size otherwise).
func plaintextFetcher(ctx context.Context, store port.ObjectStore, key string, base int64) fetchFunc {
	return func(dst []byte, start int64) error {
		length := int64(len(dst))

		body, _, err := store.GetRange(ctx, key, base+start, base+start+length-1)
		if err != nil {
			return err
		}

		readErr := func() error {
			defer func() { _ = body.Close() }()

			if _, err := io.ReadFull(body, dst); err != nil {
				return fmt.Errorf("range %s: %w", key, err)
			}

			return nil
		}()

		return readErr
	}
}

// chunkFetcher reads and decrypts the native chunks covering a plaintext range.
// Every chunk is independently sealed, so the ciphertext of chunk i starts at a
// fixed offset: base + i*(4 + chunk + 16).
type chunkFetcher struct {
	//nolint:containedctx // the fetcher is created per request and never outlives it.
	ctx    context.Context
	store  port.ObjectStore
	key    string
	dec    *encrypt.ChunkDecryptor
	base   int64
	chunk  int64
	stride int64
	ct     []byte
	plain  []byte
}

func (c *chunkFetcher) fetch(dst []byte, start int64) error {
	length := int64(len(dst))
	first := start / c.chunk

	last := (start + length - 1) / c.chunk
	if last > math.MaxUint32 {
		return fmt.Errorf("chunk index %d exceeds the format's uint32 index", last)
	}

	span := int((last - first + 1) * c.stride)
	if cap(c.ct) < span {
		c.ct = make([]byte, span)
	}

	buf := c.ct[:span]

	ctStart := c.base + first*c.stride

	body, _, err := c.store.GetRange(c.ctx, c.key, ctStart, ctStart+int64(span)-1)
	if err != nil {
		return err
	}

	n, readErr := io.ReadFull(body, buf)
	closeErr := body.Close()
	// The last chunk of an object is shorter than stride, so a short read is the
	// normal end of a window that reaches it; a truncated frame is caught below.
	if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) && !errors.Is(readErr, io.EOF) {
		return fmt.Errorf("range %s: %w", c.key, readErr)
	}

	if closeErr != nil {
		return closeErr
	}

	if err := c.decryptWindow(buf[:n], first); err != nil {
		return err
	}

	lo := start - first*c.chunk
	if lo < 0 || lo+length > int64(len(c.plain)) {
		return fmt.Errorf("chunk window %d+%d outside %d decrypted bytes", lo, length, len(c.plain))
	}

	copy(dst, c.plain[lo:lo+length])

	return nil
}

// decryptWindow decrypts the framed chunks of one window into c.plain.
func (c *chunkFetcher) decryptWindow(buf []byte, first int64) error {
	c.plain = c.plain[:0]
	idx := uint32(first) //nolint:gosec // fetch rejected an index that does not fit

	for len(buf) > 0 {
		if len(buf) < 4 {
			return fmt.Errorf("chunk %d: short frame", idx)
		}

		clen := int(binary.BigEndian.Uint32(buf))
		if clen < 16 || len(buf) < 4+clen {
			return fmt.Errorf("chunk %d: truncated frame", idx)
		}

		plain, decErr := c.dec.DecryptChunk(c.plain, idx, buf[:4+clen])
		if decErr != nil {
			return decErr
		}

		c.plain = plain
		buf = buf[4+clen:]
		idx++
	}

	return nil
}
