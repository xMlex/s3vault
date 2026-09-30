package encrypt

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/xMlex/s3vault/internal/port"
)

// DecryptAuto strips the payload encryption described by the object envelope.
// objEnc is the container's Enc as container.EncName: "none", "native" or
// "command", and is the source of truth — never the concrete type of enc.
// An empty objEnc means the object carries no S3VCTR01 container (legacy);
// there the reader's type/magic is the only signal available.
func DecryptAuto(ctx context.Context, enc port.Encryptor, objEnc string, dst io.Writer, src io.Reader) error {
	if objEnc == "" {
		return decryptLegacy(ctx, enc, dst, src)
	}

	reader := encryptorName(enc)
	if objEnc != reader {
		return fmt.Errorf("object requires encryption.mode=%s, but reader is configured for %s", objEnc, reader)
	}

	if objEnc == "none" {
		_, err := io.Copy(dst, src)
		return err
	}

	return enc.Decrypt(ctx, dst, src)
}

// decryptLegacy handles objects written before the S3VCTR01 envelope: without a
// header there is no enc field, so the local encryptor's type and the payload
// magic are all that is known. Behaviour is unchanged for backward compatibility.
func decryptLegacy(ctx context.Context, enc port.Encryptor, dst io.Writer, src io.Reader) error {
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

func encryptorName(enc port.Encryptor) string {
	type named interface{ Name() string }
	if n, ok := enc.(named); ok {
		return n.Name()
	}

	return "unknown"
}
