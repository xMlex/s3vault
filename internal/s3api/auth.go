// Package s3api serves the gateway's SigV4 S3 facade.
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
	case errors.Is(err, port.ErrAuthUnavailable):
		return s3err.ServiceUnavailable, "unavailable"
	case errors.Is(err, port.ErrAuthInternal):
		return s3err.InternalError, "internal"
	case errors.Is(err, awsig.ErrInvalidAccessKeyID):
		return s3err.InvalidAccessKeyId, "invalid_key"
	case errors.Is(err, awsig.ErrSignatureDoesNotMatch), errors.Is(err, awsig.ErrInvalidSignature):
		return s3err.SignatureDoesNotMatch, "bad_signature"
	case errors.Is(err, awsig.ErrAccessDenied), errors.Is(err, port.ErrAccessDenied):
		return s3err.AccessDenied, "denied"
	case errors.Is(err, errMissingTrailingChecksum), errors.Is(err, errUnsupportedTrailingChecksum):
		// The signature is fine; the body framing cannot be decoded as asked.
		// 403 would tell an honest client to check its credentials.
		return s3err.InvalidRequest, "bad_trailer"
	default:
		return s3err.AccessDenied, "denied"
	}
}

// AuthLayer separates authorization policy from the S3 protocol handler.
// It is an interface (not a concrete struct only) so handler tests can
// substitute it and future adapters (e.g. Postgres) can be injected without
// changing handler wiring.
type AuthLayer interface {
	Allow(ctx context.Context, pr port.Principal, op port.S3Op, bucket, key string) error
}

type authLayer struct {
	id port.S3Identity
}

func newAuthLayer(id port.S3Identity) AuthLayer {
	return &authLayer{id: id}
}

func (a *authLayer) Allow(ctx context.Context, pr port.Principal, op port.S3Op, bucket, key string) error {
	return a.id.Allow(ctx, pr, op, bucket, key)
}
