package s3api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/amwolff/awsig"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/iocopy"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
	"github.com/xMlex/s3vault/internal/service"
	"github.com/xMlex/s3vault/internal/spool"
)

// errBodyTooLarge is the exact post-read size check. http.MaxBytesReader stops
// the read a little above it (see maxBodyOverhead).
var errBodyTooLarge = errors.New("request body is over the configured limit")

func (a *API) handlePut(w http.ResponseWriter, r *http.Request, vr *awsig.V4VerifiedRequest[port.Principal], sc *scope, bucket, clientKey string) {
	arch, err := sc.archiveFor(r.Context())
	if err != nil {
		a.metric("put", "error")
		a.log.ErrorContext(r.Context(), "s3 put profile",
			slog.String("op", "s3.put"),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")

		return
	}

	body, err := requestBody(r, vr)
	if err != nil {
		a.writeAuthError(w, r, port.S3OpPut, err)
		return
	}
	// An unsigned-length body (chunked transfer, aws-chunked) is only bounded by
	// MaxBytesReader in serveHTTP; a declared length is refused before spooling,
	// so an oversized upload costs one header exchange, not a disk write.
	if r.ContentLength > a.maxBody && !isAWSChunked(r) {
		a.metric("put", "error")
		s3err.WriteError(w, r, s3err.EntityTooLarge, "")

		return
	}

	tmp, size, sum, modTime, err := spoolReader(a.spoolDir, body, a.maxBody)
	if err != nil {
		a.metric("put", "error")
		a.log.ErrorContext(r.Context(), "s3 put spool",
			slog.String("op", "s3.put"),
			slog.String("err", err.Error()),
		)

		writePutBodyError(w, r, err)

		return
	}
	defer func() { _ = os.Remove(tmp) }()

	info := domain.FileInfo{
		AbsPath: tmp,
		RelPath: filepath.Base(tmp),
		Size:    size,
		ModTime: modTime,
	}

	_, action, err := arch.UploadFile(r.Context(), info, service.ArchiveOptions{
		Root:            filepath.Dir(tmp),
		ExplicitKey:     sc.clientPath(bucket, clientKey),
		Op:              "upload",
		PlaintextSHA256: sum,
	})
	if err != nil {
		a.metric("put", "error")

		if errors.Is(err, domain.ErrInvalidPath) {
			s3err.WriteError(w, r, s3err.InvalidRequest, "")
			return
		}
		a.log.ErrorContext(r.Context(), "s3 put upload",
			slog.String("op", "s3.put"),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")
		return
	}
	switch action {
	case identity.ActionUpload, identity.ActionSkip:
		if action == identity.ActionUpload {
			// The gateway just wrote a new version, so the plaintext cache entry
			// (if any) describes the previous one. Drop it: with soft_ttl > 0 a
			// fresh hit is served without revalidation, which would hand the
			// client the old content right after a successful PUT.
			// backendKey cannot fail here — UploadFile already mapped the same key.
			backendKey, keyErr := sc.backendKey(bucket, clientKey)
			if keyErr != nil {
				a.log.WarnContext(r.Context(), "s3 put cache invalidate",
					slog.String("op", "s3.put"),
					slog.String("err", keyErr.Error()),
				)
			} else {
				sc.invalidateCache(r.Context(), backendKey, "s3.put")
			}
		}
		w.Header().Set("ETag", strconv.Quote(sum))
		w.Header().Set("x-amz-request-id", s3err.RequestID(r))
		setChecksumSHA256(w, sum)
		w.WriteHeader(http.StatusOK)
		a.metric("put", "ok")
	default:
		a.metric("put", "error")
		s3err.WriteError(w, r, s3err.InternalError, "")
	}
}

// writePutBodyError maps a failed body read to S3's answer. A checksum mismatch
// comes from the client's own trailing checksum, so it is a 400 BadDigest, not a
// server fault; awsig verifies the trailer while decoding the aws-chunked body.
func writePutBodyError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case bodyTooLarge(err):
		s3err.WriteError(w, r, s3err.EntityTooLarge, "")
	case errors.Is(err, awsig.ErrBadDigest):
		s3err.WriteError(w, r, s3err.BadDigest, "")
	case errors.Is(err, awsig.ErrInvalidDigest):
		s3err.WriteError(w, r, s3err.InvalidDigest, "")
	default:
		s3err.WriteError(w, r, s3err.InternalError, "")
	}
}

func isAWSChunked(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Content-Encoding")), "aws-chunked")
}

// spoolReader writes the request body to a temp file and returns its plaintext
// SHA-256, size and upload time. The body must be complete before the container
// header can be built: the header carries the digest and the plaintext size, and
// it precedes the payload on the wire, so the digest cannot be known while
// streaming (architecture.md, "Object format").
//
// The file deliberately gets no fsync and no Chtimes: it is read back within
// this same request and removed when the request returns, so it only has to
// survive the page cache. ModTime travels in the returned value, not in the
// file's inode.
func spoolReader(dir string, r io.Reader, limit int64) (path string, size int64, shaHex string, modTime time.Time, err error) {
	modTime = time.Now().UTC()

	f, err := spool.Create(dir, spool.PutPrefix)
	if err != nil {
		return "", 0, "", modTime, err
	}
	path = f.Name()
	defer func() {
		_ = f.Close()
		if err != nil {
			_ = os.Remove(path)
			path = ""
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return path, 0, "", modTime, err
	}
	h := sha256.New()

	n, err := spoolTo(f, r, h)
	if err != nil {
		return path, 0, "", modTime, err
	}

	if limit > 0 && n > limit {
		return path, n, "", modTime, errBodyTooLarge
	}

	return path, n, hex.EncodeToString(h.Sum(nil)), modTime, nil
}

// spoolTo streams r into dst, teeing every byte through h, and returns the
// number of bytes written. It exists so the request body has exactly one
// copy-and-hash path: handlePut hashes plaintext (SHA-256, the object identity)
// while an UploadPart hashes the part (MD5, the part ETag) — the file handling
// around it is the same, so it is not written twice.
// spoolTo copies r to dst, teeing every byte into each of hashes. Several hashes
// at once is how assembleParts gets the whole stream's SHA-256 and one part's MD5
// out of a single pass over the data.
func spoolTo(dst io.Writer, r io.Reader, hashes ...hash.Hash) (int64, error) {
	writers := make([]io.Writer, 0, len(hashes)+1)

	writers = append(writers, dst)
	for _, h := range hashes {
		writers = append(writers, h)
	}

	return iocopy.Copy(io.MultiWriter(writers...), r)
}
