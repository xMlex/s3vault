package encrypt

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/xMlex/s3vault/internal/port"
)

// DecryptAuto peeks at magic bytes and decrypts or copies plaintext.
func DecryptAuto(ctx context.Context, enc port.Encryptor, dst io.Writer, src io.Reader) error {
	head := make([]byte, len(magicV1))
	n, err := io.ReadFull(src, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("read object header: %w", err)
	}
	src = io.MultiReader(bytes.NewReader(head[:n]), src)
	if _, ok := enc.(*Command); ok {
		return enc.Decrypt(ctx, dst, src)
	}
	if n == len(magicV1) && string(head) == magicV1 {
		if _, ok := enc.(Passthrough); ok {
			return fmt.Errorf("object is encrypted; configure encryption.mode=native or command")
		}
		return enc.Decrypt(ctx, dst, src)
	}
	_, err = io.Copy(dst, src)
	return err
}
