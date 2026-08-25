package port

import (
	"context"
	"io"
	"time"
)

// CacheID uniquely identifies a plaintext cache entry (logical object + enc fingerprint).
type CacheID string

// EntryMeta is persisted beside cached plaintext for soft-TTL revalidation.
type EntryMeta struct {
	ETag         string
	SHA256       string
	LastModified time.Time
	ValidatedAt  time.Time
}

// PlaintextCache stores decrypted objects on disk.
type PlaintextCache interface {
	Get(ctx context.Context, id CacheID) (path string, hit bool, err error)
	Lookup(ctx context.Context, id CacheID) (path string, meta EntryMeta, hit bool, err error)
	Populate(ctx context.Context, id CacheID, meta EntryMeta, fill func(w io.Writer) error) (path string, err error)
	MarkValidated(ctx context.Context, id CacheID, meta EntryMeta) error
}
