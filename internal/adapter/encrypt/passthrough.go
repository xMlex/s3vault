package encrypt

import (
	"context"
	"io"

	"github.com/xMlex/s3vault/internal/port"
)

// Passthrough copies bytes unchanged (encryption.mode=none).
type Passthrough struct{}

var _ port.Encryptor = Passthrough{}

func (Passthrough) Encrypt(_ context.Context, dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	return err
}

func (Passthrough) Decrypt(_ context.Context, dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	return err
}

func (Passthrough) Name() string { return "none" }
