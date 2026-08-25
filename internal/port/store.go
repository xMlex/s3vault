package port

import (
	"context"
	"io"

	"github.com/xMlex/s3vault/internal/domain"
)

// ObjectStore is an object storage backend (S3-compatible).
type ObjectStore interface {
	Head(ctx context.Context, key string) (domain.ObjectMeta, error)
	Put(ctx context.Context, key string, r io.Reader, meta domain.PutMeta) error
	Get(ctx context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error)
	// GetRange returns bytes [start, end] inclusive (S3 Range semantics).
	GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, domain.ObjectMeta, error)
}
