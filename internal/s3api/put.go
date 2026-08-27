package s3api

import (
	"crypto/sha256"
	"encoding/hex"
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
		OnChange:        a.onChange,
		ExplicitKey:     a.clientPath(bucket, clientKey),
		Op:              "upload",
		PlaintextSHA256: sum,
	})
	if err != nil {
		a.metric("put", "error")
		if strings.Contains(err.Error(), "object exists with different checksum") {
			s3err.WriteError(w, r, s3err.AccessDenied, "object exists with different checksum")
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
		w.Header().Set("ETag", strconv.Quote(sum))
		w.Header().Set("x-amz-request-id", s3err.RequestID(r))
		w.WriteHeader(http.StatusOK)
		a.metric("put", "ok")
	case identity.ActionOmit:
		w.Header().Set("ETag", strconv.Quote(sum))
		w.Header().Set("x-amz-request-id", s3err.RequestID(r))
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
	n, err := io.Copy(io.MultiWriter(f, h), r)
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
