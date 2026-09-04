package identity

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
)

// ObjectIdentity is the store subset needed to resolve remote checksums.
// Implemented by port.ObjectStore without importing port (avoids cycles).
type ObjectIdentity interface {
	Head(ctx context.Context, key string) (domain.ObjectMeta, error)
	GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, domain.ObjectMeta, error)
}

// ResolveRemote loads object identity for Decide.
// Prefer the S3VCTR01 body header (Range GET). HEAD user-metadata is only a
// fallback for legacy objects uploaded without the container.
func ResolveRemote(ctx context.Context, store ObjectIdentity, key string) (domain.ObjectMeta, error) {
	meta, err := store.Head(ctx, key)
	if err != nil {
		return domain.ObjectMeta{}, err
	}
	if !meta.Exists {
		return meta, nil
	}

	body, rangeMeta, err := store.GetRange(ctx, key, 0, int64(container.HeaderSize-1))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return meta, nil
		}
		return domain.ObjectMeta{}, fmt.Errorf("identity range %s: %w", key, err)
	}
	defer body.Close()

	buf := make([]byte, container.HeaderSize)
	n, readErr := io.ReadFull(body, buf)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return domain.ObjectMeta{}, fmt.Errorf("identity range read %s: %w", key, readErr)
	}
	if n < container.HeaderSize || !container.IsMagic(buf) {
		return mergeRangeMeta(meta, rangeMeta), nil
	}
	hdr, err := container.Parse(buf)
	if err != nil {
		// Non-container body, or a corrupt peek while Head already carries
		// identity (legacy user-metadata / local raw sidecar).
		if errors.Is(err, container.ErrNotContainer) || meta.SHA256 != "" {
			return mergeRangeMeta(meta, rangeMeta), nil
		}
		return domain.ObjectMeta{}, fmt.Errorf("identity parse %s: %w", key, err)
	}
	meta.SHA256 = hdr.SHA256Hex()
	meta.ContentSize = hdr.PlaintextSize
	meta.Encrypted = container.EncName(hdr.Enc)
	meta.Wrap = container.WrapName(hdr.Wrap)
	meta.Provider = hdr.Provider
	meta.FormatVersion = container.FormatVersion
	meta.CryptoProThumbprint = hdr.ThumbprintHex()
	return mergeRangeMeta(meta, rangeMeta), nil
}

func mergeRangeMeta(head, rangeMeta domain.ObjectMeta) domain.ObjectMeta {
	if head.ETag == "" {
		head.ETag = rangeMeta.ETag
	}
	if head.LastModified.IsZero() {
		head.LastModified = rangeMeta.LastModified
	}
	return head
}
