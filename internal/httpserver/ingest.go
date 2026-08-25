package httpserver

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/service"
)

const headerMTime = "X-S3Vault-Mtime"

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if s.archive == nil {
		http.Error(w, "ingest unavailable", http.StatusNotImplemented)
		return
	}
	rel := r.PathValue("path")
	key, err := s.keys.FromRequestPath(rel)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	tmp, size, sum, modTime, err := spoolBody(r)
	if err != nil {
		s.log.ErrorContext(r.Context(), "ingest spool", slog.String("op", "http"), slog.String("err", err.Error()))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer func() { _ = os.Remove(tmp) }()

	info := domain.FileInfo{
		AbsPath: tmp,
		RelPath: filepath.Base(tmp),
		Size:    size,
		ModTime: modTime,
	}
	_, action, err := s.archive.UploadFile(r.Context(), info, service.ArchiveOptions{
		Root:            filepath.Dir(tmp),
		OnChange:        s.onChange,
		ExplicitKey:     rel,
		Op:              "upload",
		PlaintextSHA256: sum,
	})
	if err != nil {
		if isChecksumConflict(err) {
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		s.log.ErrorContext(r.Context(), "ingest upload",
			slog.String("op", "http"),
			slog.String("key", key),
			slog.String("err", err.Error()),
		)
		http.Error(w, "upload failed", http.StatusBadGateway)
		return
	}
	switch action {
	case identity.ActionSkip:
		w.WriteHeader(http.StatusOK)
	case identity.ActionOmit:
		// Policy skip: content differs and was not stored. Distinct from 200 so
		// remote clients do not treat this as delete-if-exists.
		w.WriteHeader(http.StatusNoContent)
	case identity.ActionUpload:
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}
}

func spoolBody(r *http.Request) (path string, size int64, shaHex string, modTime time.Time, err error) {
	modTime = time.Now().UTC()
	if raw := r.Header.Get(headerMTime); raw != "" {
		if t, parseErr := time.Parse(time.RFC3339Nano, raw); parseErr == nil {
			modTime = t
		} else if t, parseErr := time.Parse(time.RFC3339, raw); parseErr == nil {
			modTime = t
		}
	}
	f, err := os.CreateTemp("", "s3vault-ingest-*")
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
	n, err := io.Copy(io.MultiWriter(f, h), r.Body)
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

func isChecksumConflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), "object exists with different checksum")
}
