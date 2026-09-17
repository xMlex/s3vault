// Package localstore keeps objects as files under a single local directory.
//
// Default layout (container) stores the same bytes as the S3 backend
// (S3VCTR01 container plus payload). layout=raw stores plaintext as-is
// (requires encryption.mode=none). Without a container header, content-hash
// skip/dedup is unavailable.
package localstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"

	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/port"
)

const (
	fileMode fs.FileMode = 0o600
	dirMode  fs.FileMode = 0o700
)

// tmpSeq makes concurrent Put temp names distinct within a process.
var tmpSeq atomic.Uint64

// Store is a local-filesystem ObjectStore.
type Store struct {
	root   *os.Root
	dir    string
	layout string
}

var _ port.ObjectStore = (*Store)(nil)

// New creates the object directory (0700 when missing) and opens it with os.Root.
func New(cfg config.LocalConfig) (*Store, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("local object dir is required")
	}
	layout := cfg.Layout
	if layout == "" {
		layout = config.LocalLayoutContainer
	}
	switch layout {
	case config.LocalLayoutContainer, config.LocalLayoutRaw:
	default:
		return nil, fmt.Errorf("local layout %q is not supported", cfg.Layout)
	}
	if err := os.MkdirAll(cfg.Dir, dirMode); err != nil {
		return nil, fmt.Errorf("mkdir local store: %w", err)
	}
	root, err := os.OpenRoot(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("open local store root: %w", err)
	}
	// Drop temp files left behind by an interrupted Put.
	if err := root.RemoveAll(tmpDir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		_ = root.Close()
		return nil, fmt.Errorf("clean local store temp: %w", err)
	}
	return &Store{root: root, dir: cfg.Dir, layout: layout}, nil
}

// Close releases the directory file descriptor.
func (s *Store) Close() error {
	if s.root == nil {
		return nil
	}
	return s.root.Close()
}

// Dir returns the object directory.
func (s *Store) Dir() string { return s.dir }

// Layout returns the on-disk layout (container or raw).
func (s *Store) Layout() string { return s.layout }

// StoresPlaintext reports whether objects are stored as bare payload without
// the S3VCTR01 container (layout=raw). Such a store has no remote content hash,
// so callers must not hash files for skip decisions or build a container header.
func (s *Store) StoresPlaintext() bool { return s.layout == config.LocalLayoutRaw }

func (s *Store) Head(ctx context.Context, key string) (domain.ObjectMeta, error) {
	rel, err := relPath(key)
	if err != nil {
		return domain.ObjectMeta{}, err
	}
	if err := ctx.Err(); err != nil {
		return domain.ObjectMeta{}, err
	}
	fi, err := s.root.Stat(rel)
	if err != nil {
		if isNotFound(err) {
			return domain.ObjectMeta{Key: key, Exists: false}, nil
		}
		return domain.ObjectMeta{}, fmt.Errorf("head %s: %w", key, err)
	}
	if !fi.Mode().IsRegular() {
		return domain.ObjectMeta{Key: key, Exists: false}, nil
	}
	return objectMeta(key, fi), nil
}

func (s *Store) Put(ctx context.Context, key string, r io.Reader, _ domain.PutMeta) error {
	rel, err := relPath(key)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if dir := filepath.Dir(rel); dir != "." {
		if err := s.root.MkdirAll(dir, dirMode); err != nil {
			return fmt.Errorf("put %s: %w", key, err)
		}
	}
	if s.layout == config.LocalLayoutRaw {
		return s.putRaw(ctx, key, rel, r)
	}
	return s.putContainer(ctx, key, rel, r)
}

func (s *Store) putContainer(ctx context.Context, key, rel string, r io.Reader) error {
	tmp, f, err := s.createTemp()
	if err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = s.root.Remove(tmp)
		}
	}()
	if _, err := io.Copy(f, ctxReader{ctx: ctx, r: r}); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	if err := s.root.Rename(tmp, rel); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	committed = true
	return nil
}

func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error) {
	f, fi, err := s.open(ctx, key)
	if err != nil {
		return nil, domain.ObjectMeta{}, err
	}
	return f, objectMeta(key, fi), nil
}

// GetRange returns bytes [start, end] inclusive. An end past the last byte is
// clamped, and a range starting past the last byte yields an empty body rather
// than the 416 an S3 backend would raise.
//
// layout=raw ranges over the plaintext file (not a reconstructed container).
// ResolveRemote finds no S3VCTR01 magic, so content-hash skip is unavailable.
func (s *Store) GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, domain.ObjectMeta, error) {
	if start < 0 || end < start {
		return nil, domain.ObjectMeta{}, fmt.Errorf("get range %s: invalid range %d-%d", key, start, end)
	}
	f, fi, err := s.open(ctx, key)
	if err != nil {
		return nil, domain.ObjectMeta{}, err
	}
	size := fi.Size()
	var length int64
	if start < size {
		if end >= size {
			end = size - 1
		}
		length = end - start + 1
	}
	body := readCloser{Reader: io.NewSectionReader(f, start, length), Closer: f}
	return body, objectMeta(key, fi), nil
}

func (s *Store) open(ctx context.Context, key string) (*os.File, fs.FileInfo, error) {
	rel, err := relPath(key)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	f, err := s.root.Open(rel)
	if err != nil {
		if isNotFound(err) {
			return nil, nil, domain.ErrNotFound
		}
		return nil, nil, fmt.Errorf("get %s: %w", key, err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("get %s: %w", key, err)
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, domain.ErrNotFound
	}
	return f, fi, nil
}

func (s *Store) createTemp() (string, *os.File, error) {
	if err := s.root.MkdirAll(tmpDir, dirMode); err != nil {
		return "", nil, err
	}
	for range 100 {
		name := filepath.Join(tmpDir, fmt.Sprintf("put-%d-%d", os.Getpid(), tmpSeq.Add(1)))
		f, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
		if err == nil {
			return name, f, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, fmt.Errorf("no free temp file name in %s", tmpDir)
}

func objectMeta(key string, fi fs.FileInfo) domain.ObjectMeta {
	return domain.ObjectMeta{
		Key:          key,
		Exists:       true,
		Size:         fi.Size(),
		LastModified: fi.ModTime().UTC(),
		ETag:         etag(fi),
	}
}

// etag is a synthetic validator: size and mtime both change when an object is
// rewritten. Quoted like an S3 ETag so http.ServeContent accepts it. Content
// identity still comes from the S3VCTR01 header, never from this value.
func etag(fi fs.FileInfo) string {
	return `"` + strconv.FormatInt(fi.Size(), 16) + "-" + strconv.FormatInt(fi.ModTime().UnixNano(), 16) + `"`
}

// isNotFound also covers a path component that exists as a regular file
// (ENOTDIR): S3 allows both "a" and "a/b", a filesystem does not.
func isNotFound(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

type readCloser struct {
	io.Reader
	io.Closer
}

// ctxReader aborts a long Put when the caller's context is cancelled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
