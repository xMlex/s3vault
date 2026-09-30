// Package localstore keeps objects as files under a single local directory.
//
// Objects are stored byte for byte, so the same bytes reach the disk as an S3
// backend would hold. Whether those bytes carry the S3VCTR01 container is the
// writer's decision (encryption.mode), not the store's: a containerless object
// arrives here as a bare payload and is kept as one. Because such an object has
// no header to read a digest from, Head and Get derive the stored-bytes SHA-256
// by hashing the file, memoized per (path, size, mtime).
package localstore

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/port"
)

const (
	fileMode fs.FileMode = 0o600
	dirMode  fs.FileMode = 0o700

	// defaultSHACacheMax bounds the raw-layout SHA-256 memo per process. It is a
	// Store field (see Store.shaCacheMax) so tests can shrink it; on overflow the
	// least-recently-used entry is evicted deterministically.
	defaultSHACacheMax = 4096
)

// tmpSeq makes concurrent Put temp names distinct within a process.
var tmpSeq atomic.Uint64

// Store is a local-filesystem ObjectStore.
type Store struct {
	root *os.Root
	dir  string
	// shaCache memoizes the stored-bytes SHA-256 of containerless objects per
	// path, which have no header to read a digest from. shaOrder/shaElems track
	// access order so overflow evicts the least-recently-used entry
	// deterministically (problems.md P5).
	shaMu       sync.Mutex
	shaCache    map[string]shaEntry
	shaOrder    *list.List
	shaElems    map[string]*list.Element
	shaCacheMax int
}

// shaEntry is a cached digest validated by size and mtime.
type shaEntry struct {
	size  int64
	mtime int64
	sum   string
}

var _ port.ObjectStore = (*Store)(nil)

// New creates the object directory (0700 when missing) and opens it with os.Root.
func New(cfg config.LocalConfig) (*Store, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("local object dir is required")
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

	return &Store{
		root:        root,
		dir:         cfg.Dir,
		shaCache:    make(map[string]shaEntry),
		shaOrder:    list.New(),
		shaElems:    make(map[string]*list.Element),
		shaCacheMax: defaultSHACacheMax,
	}, nil
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
	meta := objectMeta(key, fi)

	sum, err := s.digestFor(ctx, key, rel, fi, nil)
	if err != nil {
		return domain.ObjectMeta{}, err
	}

	meta.SHA256 = sum

	return meta, nil
}

// Put stores the object bytes unchanged. An incoming container is kept whole,
// exactly as an S3 backend would. When the writer declared the object
// containerless it also declared its digest, so record it: the store then knows
// the object's identity and shape without guessing them from the body.
func (s *Store) Put(ctx context.Context, key string, r io.Reader, meta domain.PutMeta) error {
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

	if meta.PlaintextSHA256 != "" {
		if fi, statErr := s.root.Stat(rel); statErr == nil {
			s.rememberSHA(rel, fi, meta.PlaintextSHA256)
		}
	}

	return nil
}

func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error) {
	f, fi, err := s.open(ctx, key)
	if err != nil {
		return nil, domain.ObjectMeta{}, err
	}
	meta := objectMeta(key, fi)

	rel, err := relPath(key)
	if err != nil {
		_ = f.Close()
		return nil, domain.ObjectMeta{}, err
	}

	sum, err := s.digestFor(ctx, key, rel, fi, f)
	if err != nil {
		_ = f.Close()
		return nil, domain.ObjectMeta{}, err
	}

	meta.SHA256 = sum

	return f, meta, nil
}

// digestFor returns the digest to expose for an object, or "" when the object
// carries a container and identity must come from its header instead.
//
// A writer that stored the object in this process already declared the answer
// in PutMeta, and Put recorded it, so the memo answers first and the body's
// leading bytes are never consulted. The probe below only covers objects left by
// an earlier process, where the declared digest is gone; there a body is treated
// as a container only if it actually parses, so a plaintext file that happens to
// start with the magic is still hashed rather than misread. f may be nil, in
// which case the file is opened only when a digest is actually needed.
func (s *Store) digestFor(ctx context.Context, key, rel string, fi fs.FileInfo, f *os.File) (string, error) {
	if fi.Size() >= container.HeaderSize {
		head, err := s.readHead(key, rel, f)
		if err != nil {
			return "", err
		}

		// IsMagic matched is not enough: a container must also parse.
		if container.IsMagic(head) {
			if _, parseErr := container.Parse(head); parseErr == nil {
				return "", nil
			}
		}
	}

	if f != nil {
		return s.sha256ForFile(ctx, key, rel, fi, f)
	}

	return s.sha256For(ctx, key, rel, fi)
}

// readHead returns the object's first HeaderSize bytes, shortened for a smaller
// object. f may be nil, in which case the file is opened for the read.
func (s *Store) readHead(key, rel string, f *os.File) ([]byte, error) {
	if f == nil {
		hf, err := s.root.Open(rel)
		if err != nil {
			return nil, fmt.Errorf("head %s: %w", key, err)
		}
		defer func() { _ = hf.Close() }()

		f = hf
	}

	head := make([]byte, container.HeaderSize)

	n, err := f.ReadAt(head, 0)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("head %s: %w", key, err)
	}

	return head[:n], nil
}

// sha256For returns a containerless object's stored-bytes SHA-256, reading the
// file on a cache miss. Such an object has no container header, so this is the
// only way to expose a digest; the digest is memoized by (path, size, mtime).
// A containerless object is written only with encryption.mode=none, so the
// stored bytes are the plaintext.
func (s *Store) sha256For(ctx context.Context, key, rel string, fi fs.FileInfo) (string, error) {
	if sum, ok := s.cachedSHA(rel, fi); ok {
		return sum, nil
	}
	f, err := s.root.Open(rel)
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", key, err)
	}
	defer func() { _ = f.Close() }()
	return s.sha256ForFile(ctx, key, rel, fi, f)
}

// sha256ForFile digests f and rewinds it, so the caller can still stream the
// file. A cache hit skips the read entirely.
func (s *Store) sha256ForFile(ctx context.Context, key, rel string, fi fs.FileInfo, f *os.File) (string, error) {
	if sum, ok := s.cachedSHA(rel, fi); ok {
		return sum, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, ctxReader{ctx: ctx, r: f}); err != nil {
		return "", fmt.Errorf("hash %s: %w", key, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind %s: %w", key, err)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	s.rememberSHA(rel, fi, sum)
	return sum, nil
}

func (s *Store) cachedSHA(rel string, fi fs.FileInfo) (string, bool) {
	s.shaMu.Lock()
	defer s.shaMu.Unlock()
	e, ok := s.shaCache[rel]
	if !ok || e.size != fi.Size() || e.mtime != fi.ModTime().UnixNano() {
		return "", false
	}

	if el, ok := s.shaElems[rel]; ok {
		s.shaOrder.MoveToBack(el)
	}

	return e.sum, true
}

// rememberSHA records a digest as the most recently used entry. If the memo is
// full the least-recently-used entry is evicted, so a hot object is never
// dropped in favor of a cold one (problems.md P5).
func (s *Store) rememberSHA(rel string, fi fs.FileInfo, sum string) {
	s.shaMu.Lock()
	defer s.shaMu.Unlock()

	if el, ok := s.shaElems[rel]; ok {
		s.shaOrder.MoveToBack(el)
	} else {
		s.shaElems[rel] = s.shaOrder.PushBack(rel)
	}
	s.shaCache[rel] = shaEntry{size: fi.Size(), mtime: fi.ModTime().UnixNano(), sum: sum}
	for s.shaOrder.Len() > s.shaCacheMax {
		oldest := s.shaOrder.Front()
		s.shaOrder.Remove(oldest)
		key, _ := oldest.Value.(string)
		delete(s.shaElems, key)
		delete(s.shaCache, key)
	}
}

// GetRange returns bytes [start, end] inclusive. An end past the last byte is
// clamped, and a range starting past the last byte yields an empty body rather
// than the 416 an S3 backend would raise.
//
// The range covers the stored bytes, container prefix included, so a container
// object can be identified from its first HeaderSize bytes. No digest is exposed
// on this path.
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
// identity still comes from the S3VCTR01 header (or, for a containerless
// object, the stored-bytes digest), never from this value.
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
