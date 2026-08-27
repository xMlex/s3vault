package s3api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/amwolff/awsig"

	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
)

type credProvider struct {
	id port.S3Identity
}

func (c *credProvider) Provide(ctx context.Context, accessKeyID string) (string, port.Principal, error) {
	p, ok, err := c.id.Lookup(ctx, accessKeyID)
	if err != nil {
		return "", port.Principal{}, err
	}
	if !ok {
		return "", port.Principal{}, awsig.ErrInvalidAccessKeyID
	}
	return p.SecretKey, p, nil
}

func (a *API) writeAuthError(w http.ResponseWriter, r *http.Request, op port.S3Op, err error) {
	code, result := mapAuthError(err)
	a.metric(opMetric(op), result)
	a.log.WarnContext(r.Context(), "s3 auth failed",
		slog.String("op", "s3."+opMetric(op)),
		slog.String("err", err.Error()),
	)
	s3err.WriteError(w, r, code, "")
}

func mapAuthError(err error) (s3err.Code, string) {
	switch {
	case errors.Is(err, awsig.ErrInvalidAccessKeyID):
		return s3err.InvalidAccessKeyId, "invalid_key"
	case errors.Is(err, awsig.ErrSignatureDoesNotMatch), errors.Is(err, awsig.ErrInvalidSignature):
		return s3err.SignatureDoesNotMatch, "bad_signature"
	case errors.Is(err, awsig.ErrAccessDenied):
		return s3err.AccessDenied, "denied"
	default:
		return s3err.AccessDenied, "denied"
	}
}
