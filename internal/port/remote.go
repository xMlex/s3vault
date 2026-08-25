package port

import (
	"context"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
)

// RemoteIngest uploads plaintext to a remote s3vault HTTP server.
// requestPath is the /files/{path...} segment (no s3.prefix).
type RemoteIngest interface {
	PutFile(ctx context.Context, requestPath string, info domain.FileInfo) (identity.Action, error)
}
