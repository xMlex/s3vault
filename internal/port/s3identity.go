package port

import (
	"context"
	"errors"
)

// ErrAccessDenied is returned by S3Identity.Allow when the principal may not
// perform the operation on the given bucket/key.
var ErrAccessDenied = errors.New("s3 access denied")

// S3Op is an S3 API operation checked by S3Identity.Allow.
type S3Op int

const (
	S3OpUnknown S3Op = iota
	S3OpGet
	S3OpHead
	S3OpPut
	S3OpDelete
	S3OpList
	S3OpHeadBucket
	S3OpListBuckets
	// S3OpCreateMultipartUpload and the four after it are the multipart set.
	// The gateway assembles parts itself, so these are first-class operations of
	// the facade rather than a client-side fallback (docs/multipart.md).
	S3OpCreateMultipartUpload
	S3OpUploadPart
	S3OpCompleteMultipartUpload
	S3OpAbortMultipartUpload
	S3OpListParts
)

// Principal is an authenticated S3 API caller (frontend credentials).
type Principal struct {
	AccessKeyID string
	SecretKey   string // for SigV4 only; never log
	// AllowedBuckets restricts virtual buckets; empty means the static default only (v1).
	AllowedBuckets []string
}

// S3Identity resolves frontend access keys and authorizes operations.
// v1: static single principal; later: multi-key + bucket/prefix bindings.
type S3Identity interface {
	Lookup(ctx context.Context, accessKeyID string) (Principal, bool, error)
	Allow(ctx context.Context, p Principal, op S3Op, bucket, key string) error
}
