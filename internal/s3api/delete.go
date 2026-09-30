package s3api

import (
	"log/slog"
	"net/http"

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
	a.invalidateCache(r.Context(), backendKey, "s3.delete")

	w.Header().Set("x-amz-request-id", s3err.RequestID(r))
	w.WriteHeader(http.StatusNoContent)
	a.metric("delete", "ok")
}
