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
//
// The S3VCTR01 body header is authoritative, so the header range is the first
// call: for every object this process writes that single request answers
// existence, plaintext digest, size and encryption, and a HEAD of the facade
// costs one backend round trip instead of two. HeadObject is the fallback, and
// it is the only source of the legacy user-metadata identity that an object
// written without a container carries.
//
// A missing object needs one request too: the range answers ErrNotFound, which
// is authoritative on a strongly consistent store, so the upload path does not
// pay a HEAD before learning that there is nothing to skip.
func ResolveRemote(ctx context.Context, store ObjectIdentity, key string) (domain.ObjectMeta, error) {
	body, rangeMeta, err := store.GetRange(ctx, key, 0, int64(container.HeaderSize-1))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ObjectMeta{Key: key, Exists: false}, nil
		}

		// Not authoritative: a zero-byte object answers 416, a backend may
		// refuse ranges, or the call may have failed transiently. Let Head
		// decide existence and identity.
		return resolveFromHead(ctx, store, key, domain.ObjectMeta{}, false)
	}

	hdr, ok, readErr := readHeader(body)
	if readErr != nil {
		// A corrupt header is not proof of anything: legacy metadata on HEAD may
		// still identify the object, exactly as it did when HEAD ran first.
		meta, headErr := resolveFromHead(ctx, store, key, rangeMeta, true)
		if headErr != nil {
			return domain.ObjectMeta{}, headErr
		}

		if meta.SHA256 != "" {
			return meta, nil
		}

		return domain.ObjectMeta{}, readErr
	}

	if ok {
		return metaFromHeader(key, rangeMeta, hdr), nil
	}

	// Not a container: an object written without one keeps its identity in
	// legacy user-metadata, which only HEAD exposes.
	return resolveFromHead(ctx, store, key, rangeMeta, true)
}

// resolveFromHead is the legacy path: HEAD carries the identity of an object
// that has no S3VCTR01 header (user-metadata written by an older version).
// peeked says whether the header range already ran and returned a body that is
// not a container; when it did not, the header is fetched once HEAD confirms
// the object exists.
func resolveFromHead(
	ctx context.Context,
	store ObjectIdentity,
	key string,
	rangeMeta domain.ObjectMeta,
	peeked bool,
) (domain.ObjectMeta, error) {
	meta, err := store.Head(ctx, key)
	if err != nil {
		return domain.ObjectMeta{}, err
	}

	if !meta.Exists {
		return meta, nil
	}

	// Legacy metadata is the whole identity: the header adds nothing.
	if meta.SHA256 != "" {
		return mergeRangeMeta(meta, rangeMeta), nil
	}

	// The body was already read and is not a container: no identity remains.
	if peeked {
		return mergeRangeMeta(meta, rangeMeta), nil
	}

	body, fetched, err := store.GetRange(ctx, key, 0, int64(container.HeaderSize-1))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return meta, nil
		}

		return domain.ObjectMeta{}, fmt.Errorf("identity range %s: %w", key, err)
	}

	hdr, ok, err := readHeader(body)
	if err != nil {
		return domain.ObjectMeta{}, fmt.Errorf("identity range read %s: %w", key, err)
	}

	if !ok {
		return mergeRangeMeta(meta, fetched), nil
	}

	return metaFromHeader(key, mergeRangeMeta(meta, fetched), hdr), nil
}

// readHeader reads the first HeaderSize bytes and reports whether they are a
// parseable S3VCTR01 container.
func readHeader(body io.ReadCloser) (container.Header, bool, error) {
	defer body.Close()

	buf := make([]byte, container.HeaderSize)

	n, readErr := io.ReadFull(body, buf)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return container.Header{}, false, readErr
	}

	if n < container.HeaderSize || !container.IsMagic(buf) {
		return container.Header{}, false, nil
	}

	hdr, err := container.Parse(buf)
	if err != nil {
		// IsMagic already matched, so Parse can only fail with ErrCorruptHeader.
		return container.Header{}, false, err
	}

	return hdr, true, nil
}

// metaFromHeader overlays the container header onto the store metadata. The
// header wins for identity; the store answers the HTTP validators.
func metaFromHeader(key string, meta domain.ObjectMeta, hdr container.Header) domain.ObjectMeta {
	meta.Key = key
	meta.Exists = true
	meta.SHA256 = hdr.SHA256Hex()
	meta.ContentSize = hdr.PlaintextSize
	meta.Encrypted = container.EncName(hdr.Enc)
	meta.Wrap = container.WrapName(hdr.Wrap)
	meta.Provider = hdr.Provider
	meta.FormatVersion = container.FormatVersion
	meta.CryptoProThumbprint = hdr.ThumbprintHex()

	return meta
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
