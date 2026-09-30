package s3api

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
)

func (a *API) handleGet(w http.ResponseWriter, r *http.Request, bucket, clientKey string, headOnly bool) {
	op := "get"
	if headOnly {
		op = "head"
	}
	backendKey, err := a.backendKey(bucket, clientKey)
	if err != nil {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InvalidBucketName, "invalid object key")
		return
	}
	cached, err := a.fetch.Materialize(r.Context(), backendKey)
	if errors.Is(err, domain.ErrNotFound) {
		a.metric(op, "not_found")
		s3err.WriteError(w, r, s3err.NoSuchKey, "")
		return
	}
	if err != nil {
		a.metric(op, "error")
		a.log.ErrorContext(r.Context(), "s3 materialize",
			slog.String("op", "s3."+op),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")
		return
	}
	defer cached.Release()
	f, err := os.Open(cached.Path)
	if err != nil {
		a.metric(op, "error")
		a.log.ErrorContext(r.Context(), "s3 open cache",
			slog.String("op", "s3."+op),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")
		return
	}
	defer f.Close()

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
	if headOnly {
		st, err := f.Stat()
		if err != nil {
			a.metric(op, "error")
			s3err.WriteError(w, r, s3err.InternalError, "")
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
		if !cached.ModTime.IsZero() {
			w.Header().Set("Last-Modified", cached.ModTime.UTC().Format(http.TimeFormat))
		}
		w.WriteHeader(http.StatusOK)
		a.metric(op, "ok")
		return
	}
	http.ServeContent(w, r, cached.Name, cached.ModTime, f)
	a.metric(op, "ok")
}
