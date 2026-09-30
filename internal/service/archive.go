package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/hash"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/metrics"
	"github.com/xMlex/s3vault/internal/port"
)

// ArchiveOptions control a single archive run.
type ArchiveOptions struct {
	Root              string
	OlderThan         time.Duration
	DryRun            bool
	Workers           int
	FailFast          bool
	DeleteAfterUpload bool
	DeleteIfExists    bool   // delete local file when remote already has identical content (skip)
	ExplicitKey       string // optional path relative to s3.prefix; skips Mapper.Key
	Op                string // metrics op label; default metrics.OpArchive
	// PlaintextSHA256, when set, skips hashing the local file (the S3 facade hashed the request body while spooling).
	PlaintextSHA256 string
}

// Archive scans local files and uploads them through ObjectStore.
type Archive struct {
	scan    port.Scanner
	keys    keying.Mapper
	store   port.ObjectStore
	enc     port.Encryptor
	logger  *slog.Logger
	metrics *metrics.Collector
}

// NewArchive constructs the archive pipeline.
func NewArchive(scan port.Scanner, keys keying.Mapper, store port.ObjectStore, enc port.Encryptor, logger *slog.Logger) *Archive {
	if logger == nil {
		logger = slog.Default()
	}
	if enc == nil {
		enc = nopEncryptor{}
	}
	return &Archive{scan: scan, keys: keys, store: store, enc: enc, logger: logger}
}

// WithMetrics attaches a Prometheus collector. A nil collector is a no-op.
func (a *Archive) WithMetrics(m *metrics.Collector) *Archive {
	a.metrics = m
	return a
}

type nopEncryptor struct{}

func (nopEncryptor) Encrypt(_ context.Context, dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	return err
}

func (nopEncryptor) Decrypt(ctx context.Context, dst io.Writer, src io.Reader) error {
	return nopEncryptor{}.Encrypt(ctx, dst, src)
}

// Run walks root and processes matching files. Dry-run never calls the store.
func (a *Archive) Run(ctx context.Context, opts ArchiveOptions) (domain.ArchiveStats, error) {
	started := time.Now()
	if opts.Workers < 1 {
		opts.Workers = 1
	}
	if err := a.requireBackend(opts.DryRun); err != nil {
		return domain.ArchiveStats{}, err
	}

	var (
		found    atomic.Int64
		uploaded atomic.Int64
		skipped  atomic.Int64
		failed   atomic.Int64
		bytes    atomic.Int64
	)

	op := opts.Op
	if op == "" {
		op = metrics.OpArchive
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(opts.Workers)

	for info, err := range a.scan.Scan(ctx, opts.Root, opts.OlderThan) {
		if err != nil {
			failed.Add(1)
			a.metrics.File(op, metrics.ResultFailed)
			a.logger.Error("scan", slog.String("op", "archive"), slog.Any("err", err))
			if opts.FailFast {
				_ = g.Wait()
				return finish(&found, &uploaded, &skipped, &failed, &bytes, started), err
			}
			continue
		}
		found.Add(1)
		a.metrics.File(op, metrics.ResultFound)
		info := info
		g.Go(func() error {
			n, action, err := a.handle(ctx, opts, info)
			a.noteResult(op, action, err, n, opts.DryRun, &uploaded, &skipped, &failed, &bytes)
			if err != nil {
				a.logger.Error("process file",
					slog.String("op", "archive"),
					slog.String("path", info.RelPath),
					slog.Any("err", err),
				)
				if opts.FailFast {
					return err
				}
			}
			return nil
		})
	}

	waitErr := g.Wait()
	st := finish(&found, &uploaded, &skipped, &failed, &bytes, started)
	if waitErr != nil {
		return st, waitErr
	}
	if failed.Load() > 0 {
		return st, domain.ErrPartialFailures
	}
	return st, nil
}

// UploadFile archives one file (no mtime filter). Stats match an archive run of a single path.
// The returned action is the identity decision for that file (upload / skip / omit / fail).
func (a *Archive) UploadFile(ctx context.Context, info domain.FileInfo, opts ArchiveOptions) (domain.ArchiveStats, identity.Action, error) {
	started := time.Now()
	if opts.Op == "" {
		opts.Op = metrics.OpUpload
	}
	if err := a.requireBackend(opts.DryRun); err != nil {
		return domain.ArchiveStats{}, identity.ActionUnknown, err
	}

	var found, uploaded, skipped, failed, bytes atomic.Int64
	found.Add(1)
	a.metrics.File(opts.Op, metrics.ResultFound)

	n, action, err := a.handle(ctx, opts, info)
	a.noteResult(opts.Op, action, err, n, opts.DryRun, &uploaded, &skipped, &failed, &bytes)
	st := finish(&found, &uploaded, &skipped, &failed, &bytes, started)
	if err != nil {
		return st, action, err
	}
	return st, action, nil
}

func (a *Archive) noteResult(op string, action identity.Action, err error, n int64, dryRun bool, uploaded, skipped, failed, bytes *atomic.Int64) {
	switch {
	case err != nil:
		failed.Add(1)
		a.metrics.File(op, metrics.ResultFailed)
	case action == identity.ActionSkip:
		skipped.Add(1)
		a.metrics.File(op, metrics.ResultSkipped)
	case action == identity.ActionUpload && !dryRun:
		uploaded.Add(1)
		bytes.Add(n)
		a.metrics.File(op, metrics.ResultUploaded)
		a.metrics.AddBytes(metrics.DirUpload, n)
	}
}

func (a *Archive) requireBackend(dryRun bool) error {
	if dryRun {
		return nil
	}

	if a.store == nil {
		return domain.ErrStoreRequired
	}

	return nil
}

func (a *Archive) objectKey(opts ArchiveOptions, info domain.FileInfo) (string, error) {
	if opts.ExplicitKey != "" {
		return a.keys.FromRequestPath(opts.ExplicitKey)
	}
	return a.keys.Key(opts.Root, info.AbsPath)
}

func (a *Archive) handle(ctx context.Context, opts ArchiveOptions, info domain.FileInfo) (int64, identity.Action, error) {
	if err := ctx.Err(); err != nil {
		return 0, identity.ActionUnknown, err
	}
	key, err := a.objectKey(opts, info)
	if err != nil {
		return 0, identity.ActionUnknown, fmt.Errorf("object key: %w", err)
	}
	op := opts.Op
	if op == "" {
		op = metrics.OpArchive
	}
	a.logger.Info("file",
		slog.String("op", op),
		slog.String("path", info.RelPath),
		slog.String("key", key),
		slog.Int64("size", info.Size),
		slog.Bool("dry_run", opts.DryRun),
	)
	if opts.DryRun {
		return 0, identity.ActionUpload, nil
	}

	plaintext := a.storesPlaintext()
	sum, remote, err := a.resolveRemote(ctx, opts, info, key, plaintext)
	if err != nil {
		return 0, identity.ActionUnknown, err
	}
	action := identity.Decide(sum, info.Size, remote)
	switch action {
	case identity.ActionSkip:
		a.logger.Info("skip existing", slog.String("op", op), slog.String("key", key), slog.String("action", actionName(action)))
		if err := a.maybeDeleteLocal(opts, info, action); err != nil {
			return 0, action, err
		}
		return 0, action, nil
	}

	if err := a.upload(ctx, key, info, sum, plaintext); err != nil {
		return 0, identity.ActionUpload, err
	}
	if err := a.maybeDeleteLocal(opts, info, identity.ActionUpload); err != nil {
		return info.Size, identity.ActionUpload, err
	}
	return info.Size, identity.ActionUpload, nil
}

// maybeDeleteLocal removes the source file when the matching delete flag is set.
// ActionSkip (identical remote) → DeleteIfExists; ActionUpload → DeleteAfterUpload.
func (a *Archive) maybeDeleteLocal(opts ArchiveOptions, info domain.FileInfo, action identity.Action) error {
	switch {
	case action == identity.ActionUpload && opts.DeleteAfterUpload:
	case action == identity.ActionSkip && opts.DeleteIfExists:
	default:
		return nil
	}
	if err := os.Remove(info.AbsPath); err != nil {
		return fmt.Errorf("delete local file: %w", err)
	}
	return nil
}

func actionName(a identity.Action) string {
	switch a {
	case identity.ActionUpload:
		return "upload"
	case identity.ActionSkip:
		return "skip"
	default:
		return "unknown"
	}
}

// plaintextStore is an ObjectStore that persists bare payload without the
// S3VCTR01 container (local layout=raw).
type plaintextStore interface {
	StoresPlaintext() bool
}

// storesPlaintext reports whether the backend drops the container header, so
// the pipeline can skip hashing and the range peek.
func (a *Archive) storesPlaintext() bool {
	ps, ok := a.store.(plaintextStore)
	return ok && ps.StoresPlaintext()
}

// resolveRemote returns the local plaintext SHA-256 and the remote identity.
// For a plaintext store there is no remote content hash, so hashing and the
// range peek are wasted I/O and Head alone drives the decision.
func (a *Archive) resolveRemote(ctx context.Context, opts ArchiveOptions, info domain.FileInfo, key string, plaintext bool) (string, domain.ObjectMeta, error) {
	if plaintext {
		meta, err := a.store.Head(ctx, key)
		if err != nil {
			return "", domain.ObjectMeta{}, err
		}
		return "", meta, nil
	}
	sum := opts.PlaintextSHA256
	if sum == "" {
		var err error
		sum, err = hash.FileSHA256(info.AbsPath)
		if err != nil {
			return "", domain.ObjectMeta{}, fmt.Errorf("checksum: %w", err)
		}
	}
	meta, err := identity.ResolveRemote(ctx, a.store, key)
	if err != nil {
		return "", domain.ObjectMeta{}, err
	}
	return sum, meta, nil
}

func (a *Archive) upload(ctx context.Context, key string, info domain.FileInfo, sum string, plaintext bool) error {
	started := time.Now()
	var hdrBytes []byte
	if !plaintext {
		var err error
		hdrBytes, err = buildContainerHeader(sum, info.Size, info.ModTime,
			encryptName(a.enc), encryptWrap(a.enc), encryptProvider(a.enc), cryptoProThumbprint(a.enc))
		if err != nil {
			return err
		}
	}

	pr, wait := a.encryptPipe(ctx, info.AbsPath)

	body := pr
	if !plaintext {
		body = io.MultiReader(bytes.NewReader(hdrBytes), pr)
	}

	putErr := a.store.Put(ctx, key, body, domain.PutMeta{
		ContentType: mime.TypeByExtension(filepath.Ext(info.AbsPath)),
	})
	waitErr := wait()

	if putErr != nil {
		return putErr
	}

	if waitErr != nil {
		return waitErr
	}

	a.metrics.ObserveUpload(time.Since(started), info.Size)

	return nil
}

// encryptPipe opens path and streams a.enc.Encrypt over it through an io.Pipe.
// The returned reader yields the ciphertext; wait joins the producer goroutine
// and must be called exactly once after the reader is consumed (or abandoned).
func (a *Archive) encryptPipe(ctx context.Context, path string) (io.Reader, func() error) {
	pr, pw := io.Pipe()
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		f, err := os.Open(path) //nolint:gosec // path comes from the local scanner, not user input
		if err != nil {
			_ = pw.CloseWithError(err)
			return err
		}
		defer f.Close()
		err = a.enc.Encrypt(ctx, pw, f)
		_ = pw.CloseWithError(err)
		return err
	})

	return pr, func() error {
		_ = pr.Close()
		return g.Wait()
	}
}

func buildContainerHeader(shaHex string, size int64, mtime time.Time, encName, wrapName, provider, thumbHex string) ([]byte, error) {
	sum, err := container.SHA256FromHex(shaHex)
	if err != nil {
		return nil, err
	}
	tp, err := container.ThumbprintFromHex(thumbHex)
	if err != nil {
		return nil, err
	}
	return container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: size,
		SHA256:        sum,
		Enc:           container.EncFromName(encName),
		Wrap:          container.WrapFromName(wrapName),
		Provider:      provider,
		Thumbprint:    tp,
		SourceMTime:   mtime,
	})
}

func encryptName(enc port.Encryptor) string {
	type named interface {
		Name() string
	}
	if n, ok := enc.(named); ok {
		return n.Name()
	}
	return "unknown"
}

func encryptWrap(enc port.Encryptor) string {
	type withWrap interface {
		Wrap() string
	}
	if w, ok := enc.(withWrap); ok {
		return w.Wrap()
	}
	return ""
}

func encryptProvider(enc port.Encryptor) string {
	type withProvider interface {
		Provider() string
	}
	if p, ok := enc.(withProvider); ok {
		return p.Provider()
	}
	return ""
}

func cryptoProThumbprint(enc port.Encryptor) string {
	type withTP interface {
		CryptoProThumbprint() string
	}
	if t, ok := enc.(withTP); ok {
		return t.CryptoProThumbprint()
	}
	return ""
}

func finish(found, uploaded, skipped, failed, bytes *atomic.Int64, started time.Time) domain.ArchiveStats {
	return domain.ArchiveStats{
		Found:         int(found.Load()),
		Uploaded:      int(uploaded.Load()),
		Skipped:       int(skipped.Load()),
		Failed:        int(failed.Load()),
		BytesUploaded: bytes.Load(),
		Duration:      time.Since(started),
	}
}
