package port

import (
	"context"
	"io"
)

// Encryptor transforms a stream. Implementations must not buffer the whole payload.
type Encryptor interface {
	Encrypt(ctx context.Context, dst io.Writer, src io.Reader) error
	Decrypt(ctx context.Context, dst io.Writer, src io.Reader) error
}
