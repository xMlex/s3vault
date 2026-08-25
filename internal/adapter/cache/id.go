package cache

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"

	"github.com/xMlex/s3vault/internal/port"
)

// ID is SHA-256(bucket, object key, enc fingerprint) as hex.
// Object version (ETag / plaintext SHA-256) is stored in the sidecar for soft-TTL revalidation,
// so a cache hit within soft_ttl needs no S3 round-trip.
func ID(bucket, key, encFP string) port.CacheID {
	h := sha256.New()
	writeField(h, bucket)
	writeField(h, key)
	writeField(h, encFP)
	return port.CacheID(hex.EncodeToString(h.Sum(nil)))
}

func writeField(w io.Writer, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	_, _ = w.Write(n[:])
	_, _ = io.WriteString(w, s)
}
