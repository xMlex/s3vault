package s3api

import (
	"log/slog"
	"net/http"

	"github.com/xMlex/s3vault/internal/adapter/cache"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
)

func (a *API) handleDelete(w http.ResponseWriter, r *http.Request, bucket, clientKey string) {
	backendKey, err := a.backendKey(bucket, clientKey)
	if err != nil {
		a.metric("delete", "error")
		s3err.WriteError(w, r, s3err.InvalidBucketName, "invalid object key")
		return
	}
	if err := a.store.Delete(r.Context(), backendKey); err != nil {
		a.metric("delete", "error")
		a.log.ErrorContext(r.Context(), "s3 delete",
			slog.String("op", "s3.delete"),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")
		return
	}
	if a.cache != nil {
		id := cache.ID(a.bucketBackend, backendKey, a.encFP)
		if err := a.cache.Remove(r.Context(), id); err != nil {
			a.log.WarnContext(r.Context(), "s3 cache invalidate",
				slog.String("op", "s3.delete"),
				slog.String("err", err.Error()),
			)
		}
	}
	w.Header().Set("x-amz-request-id", s3err.RequestID(r))
	w.WriteHeader(http.StatusNoContent)
	a.metric("delete", "ok")
}
