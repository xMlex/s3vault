package s3api

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/amwolff/awsig"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
	"github.com/xMlex/s3vault/internal/service"
)

func (a *API) handlePut(w http.ResponseWriter, r *http.Request, vr *awsig.V4VerifiedRequest[port.Principal], bucket, clientKey string) {
	body, err := vr.Reader()
	if err != nil {
		a.writeAuthError(w, r, port.S3OpPut, err)
		return
	}
	tmp, size, sum, modTime, err := spoolReader(body)
	if err != nil {
		a.metric("put", "error")
		a.log.ErrorContext(r.Context(), "s3 put spool",
			slog.String("op", "s3.put"),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")
		return
	}
	defer func() { _ = os.Remove(tmp) }()

	info := domain.FileInfo{
		AbsPath: tmp,
		RelPath: filepath.Base(tmp),
		Size:    size,
		ModTime: modTime,
	}
	_, action, err := a.archive.UploadFile(r.Context(), info, service.ArchiveOptions{
		Root:            filepath.Dir(tmp),
		ExplicitKey:     a.clientPath(bucket, clientKey),
		Op:              "upload",
		PlaintextSHA256: sum,
	})
	if err != nil {
		a.metric("put", "error")
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
			backendKey, keyErr := a.backendKey(bucket, clientKey)
			if keyErr != nil {
				a.log.WarnContext(r.Context(), "s3 put cache invalidate",
					slog.String("op", "s3.put"),
					slog.String("err", keyErr.Error()),
				)
			} else {
				a.invalidateCache(r.Context(), backendKey, "s3.put")
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

func spoolReader(r io.Reader) (path string, size int64, shaHex string, modTime time.Time, err error) {
	modTime = time.Now().UTC()
	f, err := os.CreateTemp("", "s3vault-s3put-*")
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
	if err = f.Sync(); err != nil {
		return path, 0, "", modTime, err
	}
	if err = os.Chtimes(path, modTime, modTime); err != nil {
		return path, 0, "", modTime, err
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

	return io.Copy(io.MultiWriter(writers...), r)
}
