package localstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/xMlex/s3vault/internal/container"
)

// peekContainer reads up to HeaderSize bytes. When the prefix is a valid
// S3VCTR01 header, rest is positioned at the payload: raw stores the bare
// payload, whether it is plaintext (mode=none) or ciphertext (native/command).
// Otherwise rest restores the peeked bytes for a passthrough write.
func peekContainer(r io.Reader) (rest io.Reader, err error) {
	buf := make([]byte, container.HeaderSize)
	n, readErr := io.ReadFull(r, buf)
	restored := io.MultiReader(bytes.NewReader(buf[:n]), r)
	if readErr != nil && readErr != io.EOF && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return nil, readErr
	}
	if n < container.HeaderSize || !container.IsMagic(buf) {
		return restored, nil
	}
	// IsMagic already matched, so Parse can only fail with ErrCorruptHeader.
	if _, parseErr := container.Parse(buf); parseErr != nil {
		return nil, parseErr
	}
	return r, nil
}

func (s *Store) putRaw(ctx context.Context, key, rel string, r io.Reader) error {
	rest, err := peekContainer(ctxReader{ctx: ctx, r: r})
	if err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}

	tmpObj, f, err := s.createTemp()
	if err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = s.root.Remove(tmpObj)
		}
	}()

	if _, err := io.Copy(f, ctxReader{ctx: ctx, r: rest}); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	if err := s.root.Rename(tmpObj, rel); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	committed = true
	return nil
}
