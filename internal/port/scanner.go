package port

import (
	"context"
	"iter"
	"time"

	"github.com/xMlex/s3vault/internal/domain"
)

// Scanner walks a directory tree and yields files older than a threshold.
type Scanner interface {
	Scan(ctx context.Context, root string, olderThan time.Duration) iter.Seq2[domain.FileInfo, error]
}
