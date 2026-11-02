// Package iocopy copies streams through one pooled buffer size instead of the
// 32 KiB heap buffer io.Copy allocates per call.
//
// The hot paths here move whole objects: a PutObject body is spooled and read
// back, an object is decrypted into a cache file, a ciphertext stream crosses an
// io.Pipe. At 32 KiB each of those costs ~32k read/write syscalls per GiB; at
// 256 KiB it is ~4k, and the buffer is reused rather than allocated per copy.
package iocopy

import (
	"io"
	"sync"
)

// BufferSize is the copy buffer. It is a multiple of the default AES-GCM chunk
// size (64 KiB), so a chunked decrypt crosses a buffered writer in whole chunks.
const BufferSize = 256 << 10

var pool = sync.Pool{
	New: func() any {
		b := make([]byte, BufferSize)
		return &b
	},
}

// Copy is io.Copy with a pooled BufferSize buffer. Reader/Writer shortcuts
// (WriteTo/ReadFrom) are still used when both ends implement them.
func Copy(dst io.Writer, src io.Reader) (int64, error) {
	bp, _ := pool.Get().(*[]byte)
	if bp == nil {
		buf := make([]byte, BufferSize)
		bp = &buf
	}
	defer pool.Put(bp)

	return io.CopyBuffer(dst, src, *bp)
}
