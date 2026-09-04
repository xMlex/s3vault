package localstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
)

// metaSuffix is the adjacent identity sidecar for layout=raw.
// Object key "a/b.log" → file "a/b.log" + sidecar "a/b.log.s3vault-meta".
const metaSuffix = ".s3vault-meta"

// layoutRaw is config.LocalLayoutRaw (kept as a literal to avoid repeating the
// import name at every call site).
const layoutRaw = "raw"

func metaRel(rel string) string { return rel + metaSuffix }

func applySidecar(meta domain.ObjectMeta, hdr container.Header) domain.ObjectMeta {
	meta.SHA256 = hdr.SHA256Hex()
	meta.ContentSize = hdr.PlaintextSize
	meta.Encrypted = container.EncName(hdr.Enc)
	meta.Wrap = container.WrapName(hdr.Wrap)
	meta.Provider = hdr.Provider
	meta.FormatVersion = container.FormatVersion
	meta.CryptoProThumbprint = hdr.ThumbprintHex()
	return meta
}

func (s *Store) readSidecar(rel string) (container.Header, bool, error) {
	f, err := s.root.Open(metaRel(rel))
	if err != nil {
		if isNotFound(err) {
			return container.Header{}, false, nil
		}
		return container.Header{}, false, fmt.Errorf("read sidecar: %w", err)
	}
	defer f.Close()
	buf := make([]byte, container.HeaderSize)
	if _, err := io.ReadFull(f, buf); err != nil {
		return container.Header{}, false, fmt.Errorf("read sidecar: %w", err)
	}
	hdr, err := container.Parse(buf)
	if err != nil {
		return container.Header{}, false, fmt.Errorf("parse sidecar: %w", err)
	}
	return hdr, true, nil
}

func (s *Store) removeSidecar(rel string) {
	_ = s.root.Remove(metaRel(rel))
}

func (s *Store) withSidecar(rel string, meta domain.ObjectMeta) (domain.ObjectMeta, error) {
	if s.layout != layoutRaw {
		return meta, nil
	}
	hdr, ok, err := s.readSidecar(rel)
	if err != nil {
		return domain.ObjectMeta{}, err
	}
	if ok {
		meta = applySidecar(meta, hdr)
	}
	return meta, nil
}

// peekContainer reads up to HeaderSize bytes. When ok is true, hdr is a valid
// EncNone S3VCTR01 header and rest is positioned at the payload. Otherwise
// rest restores the peeked bytes for a passthrough write.
func peekContainer(r io.Reader) (hdr []byte, rest io.Reader, ok bool, err error) {
	buf := make([]byte, container.HeaderSize)
	n, readErr := io.ReadFull(r, buf)
	restored := io.MultiReader(bytes.NewReader(buf[:n]), r)
	if readErr != nil && readErr != io.EOF && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return nil, nil, false, readErr
	}
	if n < container.HeaderSize || !container.IsMagic(buf) {
		return nil, restored, false, nil
	}
	h, parseErr := container.Parse(buf)
	if parseErr != nil {
		if errors.Is(parseErr, container.ErrNotContainer) {
			return nil, restored, false, nil
		}
		return nil, nil, false, parseErr
	}
	if h.Enc != container.EncNone {
		return nil, nil, false, fmt.Errorf("layout=raw rejects encrypted objects (enc=%s)", container.EncName(h.Enc))
	}
	return buf, r, true, nil
}

func (s *Store) putRaw(ctx context.Context, key, rel string, r io.Reader) error {
	hdr, rest, stripped, err := peekContainer(ctxReader{ctx: ctx, r: r})
	if err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}

	tmpObj, f, err := s.createTemp()
	if err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	committed := false
	var tmpMeta string
	defer func() {
		if !committed {
			_ = f.Close()
			_ = s.root.Remove(tmpObj)
			if tmpMeta != "" {
				_ = s.root.Remove(tmpMeta)
			}
		}
	}()

	if _, err := io.Copy(f, rest); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}

	if stripped {
		var mf *os.File
		tmpMeta, mf, err = s.createTemp()
		if err != nil {
			return fmt.Errorf("put %s: %w", key, err)
		}
		if _, err := mf.Write(hdr); err != nil {
			_ = mf.Close()
			return fmt.Errorf("put %s: %w", key, err)
		}
		if err := mf.Sync(); err != nil {
			_ = mf.Close()
			return fmt.Errorf("put %s: %w", key, err)
		}
		if err := mf.Close(); err != nil {
			return fmt.Errorf("put %s: %w", key, err)
		}
	}

	if err := s.root.Rename(tmpObj, rel); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	if stripped {
		if err := s.root.Rename(tmpMeta, metaRel(rel)); err != nil {
			_ = s.root.Remove(rel)
			return fmt.Errorf("put %s: %w", key, err)
		}
	} else {
		s.removeSidecar(rel)
	}
	committed = true
	return nil
}
