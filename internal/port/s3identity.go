package port

import (
	"context"
	"encoding/json"
	"errors"
)

// ErrAccessDenied is returned by S3Identity.Allow when the principal may not
// perform the operation on the given bucket/key.
var ErrAccessDenied = errors.New("s3 access denied")

// ErrAuthUnavailable marks a temporary failure of the identity backend (for
// example, PostgreSQL is unreachable). It is rendered as 503, never as 403: an
// infrastructure failure must not look like an authorization decision.
var ErrAuthUnavailable = errors.New("s3 auth backend unavailable")

// ErrAuthInternal marks a corrupt or misconfigured identity record, such as a
// secret that does not decrypt with the configured master key. It is rendered
// as 500.
var ErrAuthInternal = errors.New("s3 auth backend internal error")

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

// SSEKMS is the destination's server-side encryption with AWS KMS. Its
// presence means "send SSE-KMS headers on write"; an absent value means the
// destination's own defaults apply and no SSE headers are sent.
type SSEKMS struct {
	KeyID     string            // empty = the bucket's default KMS key
	Context   map[string]string // optional encryption context
	BucketKey bool              // optional S3 Bucket Key
}

// S3Target is a user's optional destination storage. It replaces the gateway's
// global s3.* config for that user; there is no field-by-field merge, so a
// missing credential never falls back to the global one.
type S3Target struct {
	Endpoint     string
	Region       string
	Bucket       string
	Prefix       string
	AccessKey    string
	SecretKey    string // never log
	SessionToken string // never log
	PathStyle    bool
	SSEKMS       *SSEKMS // nil = do not use SSE-KMS
	StorageClass string  // empty = do not send x-amz-storage-class
}

// UserPolicy is the per-user policy resolved from the identity backend.
//
// The zero value belongs to a static single-principal deployment: no user id,
// no transparent prefix, and the gateway's global encryption config. A non-zero
// ID means the principal came from the users table.
type UserPolicy struct {
	ID     int64
	Prefix string
	// Encryption is the user's full encryption profile as stored in the
	// database. Nil or an empty mode means "use the gateway default".
	Encryption json.RawMessage
	// Target is the user's destination storage. Nil means the gateway's
	// global s3.* backend.
	Target *S3Target
}

// Principal is an authenticated S3 API caller (frontend credentials).
type Principal struct {
	AccessKeyID string
	SecretKey   string // for SigV4 only; never log
	// AllowedBuckets restricts virtual buckets; empty means the static default only (v1).
	AllowedBuckets []string
	User           UserPolicy
}

// S3Identity resolves frontend access keys and authorizes operations.
// v1: static single principal; later: multi-key + bucket/prefix bindings.
type S3Identity interface {
	Lookup(ctx context.Context, accessKeyID string) (Principal, bool, error)
	Allow(ctx context.Context, p Principal, op S3Op, bucket, key string) error
}
