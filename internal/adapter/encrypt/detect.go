package encrypt

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/xMlex/s3vault/internal/port"
)

const (
	// opensslMagic is the envelope marker OpenSSL writes in front of a salted
	// ciphertext. It is what a command-mode payload looks like without the
	// S3VCTR01 header, and it is distinct from the native magic above.
	opensslMagic = "Salted__"
)

// DecryptAuto strips the payload encryption described by the object envelope.
// objEnc is the container's Enc as container.EncName: "none", "native" or
// "command", and is the source of truth — never the concrete type of enc. An
// empty objEnc means the object carries no S3VCTR01 container; there the
// reader's type/magic is the only signal available.
//
// A container whose enc the reader does not have is a layer it cannot remove. The
// format carries no "whose layer" marker, so that can only mean the read and write
// paths disagree — a gateway on one and not the other, or a mode that drifted —
// and it is reported rather than served as plaintext.
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

// decryptLegacy handles objects written without the S3VCTR01 container: without
// a header there is no enc field, so the local encryptor's type and the payload
// magic are all that is known. encryption.mode=none writes such objects itself,
// which is why the copy path below is the common case and not merely a
// compatibility shim.
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

	if _, plain := enc.(Passthrough); plain {
		if n == len(magicV1) && string(head) == magicV1 {
			return fmt.Errorf("object is encrypted; configure encryption.mode=native or command")
		}
		// OpenSSL's envelope marker, as emitted for a command-mode ciphertext.
		// It is not the native magic, so without this check it would be copied
		// out as plaintext — the one containerless case that cannot fail loudly
		// any other way. An 8-byte prefix is not proof of ciphertext, so the
		// message names both readings rather than asserting one.
		if n >= len(opensslMagic) && string(head[:len(opensslMagic)]) == opensslMagic {
			return fmt.Errorf("object starts with the openssl envelope marker (%s) and carries no S3VCTR01 container; "+
				"if it is ciphertext, configure encryption.mode=command, otherwise it cannot be read as plaintext",
				opensslMagic)
		}
	} else if n == len(magicV1) && string(head) == magicV1 {
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
