package s3api

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
	"github.com/xMlex/s3vault/internal/service"
)

func (a *API) handleGet(w http.ResponseWriter, r *http.Request, sc *scope, bucket, clientKey string, headOnly bool) {
	op := "get"
	if headOnly {
		op = "head"
	}

	backendKey, err := sc.backendKey(bucket, clientKey)
	if err != nil {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InvalidBucketName, "invalid object key")
		return
	}

	fetch, err := sc.fetchFor(r.Context())
	if err != nil {
		a.metric(op, "error")
		a.log.ErrorContext(r.Context(), "s3 fetch profile",
			slog.String("op", "s3."+op),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")

		return
	}

	// A HEAD is answered from object metadata alone: no download, no decrypt,
	// no temp file. The body is not needed to state its length, type and digest,
	// and the container header carries all three.
	if headOnly {
		a.handleHead(w, r, fetch, backendKey)
		return
	}

	// Open serves from the cache when one is configured, and otherwise reads
	// through ranged backend requests: ServeContent asks for the bytes it needs,
	// so a ranged GET no longer downloads and decrypts the whole object first.
	rc, cached, err := fetch.Open(r.Context(), backendKey)
	if errors.Is(err, domain.ErrNotFound) {
		a.metric(op, "not_found")
		s3err.WriteError(w, r, s3err.NoSuchKey, "")
		return
	}
	if err != nil {
		a.metric(op, "error")
		if errors.Is(err, domain.ErrInvalidPath) {
			s3err.WriteError(w, r, s3err.NoSuchKey, "")
			return
		}
		a.log.ErrorContext(r.Context(), "s3 open",
			slog.String("op", "s3."+op),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")
		return
	}
	defer func() { _ = rc.Close() }()

	setObjectHeaders(w, r, cached)
	http.ServeContent(w, r, cached.Name, cached.ModTime, rc)
	a.metric(op, "ok")
}

func (a *API) handleHead(w http.ResponseWriter, r *http.Request, fetch *service.Fetch, backendKey string) {
	cached, err := fetch.Stat(r.Context(), backendKey)
	if errors.Is(err, domain.ErrNotFound) {
		a.metric("head", "not_found")
		s3err.WriteError(w, r, s3err.NoSuchKey, "")

		return
	}
	if err != nil {
		a.metric("head", "error")
		if errors.Is(err, domain.ErrInvalidPath) {
			// A reserved key (for example .s3vault-index/...) is not an object
			// and must not turn into a 500 in the log.
			s3err.WriteError(w, r, s3err.NoSuchKey, "")

			return
		}
		a.log.ErrorContext(r.Context(), "s3 stat",
			slog.String("op", "s3.head"),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")

		return
	}

	setObjectHeaders(w, r, cached)
	w.Header().Set("Content-Length", strconv.FormatInt(cached.Size, 10))

	if !cached.ModTime.IsZero() {
		w.Header().Set("Last-Modified", cached.ModTime.UTC().Format(http.TimeFormat))
	}

	w.WriteHeader(http.StatusOK)
	a.metric("head", "ok")
}

// setObjectHeaders sets the response headers shared by GET and HEAD.
func setObjectHeaders(w http.ResponseWriter, r *http.Request, cached service.CachedPlaintext) {
	w.Header().Set("x-amz-request-id", s3err.RequestID(r))
	w.Header().Set("ETag", strconv.Quote(cached.ETag))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Only on a whole-object response. A 206 carries a range, and
	// x-amz-checksum-sha256 describes the bytes in the body: advertising the
	// whole object's digest there is a false claim, and clients that verify
	// checksums (aws s3 cp downloads large objects in ranges) reject the
	// response instead of the file. S3 answers a ranged GET with the digest *of
	// the range*; computing that per range would mean reading it on every ranged
	// read, so the header is simply omitted — same as a store that has no
	// checksum to give.
	if r.Header.Get("Range") == "" {
		setChecksumSHA256(w, cached.SHA256)
	}
}
