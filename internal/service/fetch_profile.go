package service

import (
	"bufio"
	"context"
	"fmt"
	"io"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/port"
)

// encryptorFor selects the profile for an object whose S3VCTR01 header names
// objEnc. A per-user view has a primary profile and, when its algorithm differs
// from the gateway default, a fallback. The base Fetch (CLI download, static
// gateway) keeps the historical single-encryptor behaviour.
func (f *Fetch) encryptorFor(objEnc string) (port.Encryptor, error) {
	if !f.managed {
		return f.enc, nil
	}

	switch objEnc {
	case "":
		return f.enc, nil
	case encrypt.NameNone:
		// None is not a cryptographic layer. Reading it is safe and does not
		// require the user's profile to be none; the prefix still authorizes the
		// object.
		return encrypt.Passthrough{}, nil
	}

	if encrypt.Name(f.enc) == objEnc {
		return f.enc, nil
	}

	if f.fallback != nil && encrypt.Name(f.fallback) == objEnc {
		return f.fallback, nil
	}

	return nil, fmt.Errorf("object requires encryption.mode=%s; user profile=%s, gateway default=%s",
		objEnc, encrypt.Name(f.enc), fallbackName(f.fallback))
}

func fallbackName(enc port.Encryptor) string {
	if enc == nil {
		return encrypt.NameNone
	}

	return encrypt.Name(enc)
}

// legacyEncryptor classifies a containerless object by its magic. Plaintext is
// readable by every profile; native and command ciphertext need a matching
// profile. This prevents a command profile from being run on plaintext.
func (f *Fetch) legacyEncryptor(prefix []byte) (port.Encryptor, error) {
	if !f.managed {
		return f.enc, nil
	}

	kind := encrypt.LegacyKind(prefix)
	if kind == encrypt.NameNone {
		return encrypt.Passthrough{}, nil
	}

	if encrypt.Name(f.enc) == kind {
		return f.enc, nil
	}

	if f.fallback != nil && encrypt.Name(f.fallback) == kind {
		return f.fallback, nil
	}

	return nil, fmt.Errorf("containerless object is %s ciphertext; user profile=%s, gateway default=%s",
		kind, encrypt.Name(f.enc), fallbackName(f.fallback))
}

// decryptStream is DecryptAuto with profile selection. For a container object
// objEnc comes from S3VCTR01; for a legacy object the stream is peeked to pick
// the matching profile before any bytes are copied out.
func (f *Fetch) decryptStream(ctx context.Context, dst io.Writer, src io.Reader, objEnc string) error {
	if !f.managed {
		return encrypt.DecryptAuto(ctx, f.enc, objEnc, dst, src)
	}

	if objEnc != "" {
		enc, err := f.encryptorFor(objEnc)
		if err != nil {
			return err
		}

		return encrypt.DecryptAuto(ctx, enc, objEnc, dst, src)
	}

	br := bufio.NewReader(src)

	prefix, _ := br.Peek(8)

	enc, err := f.legacyEncryptor(prefix)
	if err != nil {
		return err
	}

	if encrypt.Name(enc) == encrypt.NameNone {
		_, err := io.Copy(dst, br)

		return err
	}

	return encrypt.DecryptAuto(ctx, enc, "", dst, br)
}
