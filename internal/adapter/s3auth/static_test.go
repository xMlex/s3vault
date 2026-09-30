package s3auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/s3auth"
	"github.com/xMlex/s3vault/internal/port"
)

func TestStaticLookupAndAllow(t *testing.T) {
	t.Parallel()
	s := &s3auth.Static{
		AccessKey: "ak",
		SecretKey: "sk",
		Bucket:    "vault",
	}
	p, ok, err := s.Lookup(context.Background(), "ak")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "sk", p.SecretKey)

	_, ok, err = s.Lookup(context.Background(), "nope")
	require.NoError(t, err)
	assert.False(t, ok)

	require.NoError(t, s.Allow(context.Background(), p, port.S3OpGet, "vault", "a"))
	require.ErrorIs(t, s.Allow(context.Background(), p, port.S3OpGet, "other", "a"), port.ErrAccessDenied)
	require.NoError(t, s.Allow(context.Background(), p, port.S3OpListBuckets, "", ""))
}

// TestStaticAllowIgnoresOperation pins that the v1 identity authorises on the
// bucket alone. It exists because the multipart operations were added to
// port.S3Op without touching this adapter: without the test, a reader would
// reasonably suspect the new operations had simply been forgotten by the
// authorisation layer, and "fix" it by refusing them.
//
// Authorising on the operation is deliberately not v1's job. With one access key
// and one virtual bucket there is nothing to distinguish — the key already grants
// every operation on the bucket. The per-upload check that is *not* redundant
// (an upload id is a capability bound to the principal that created it) lives in
// the facade's session registry, not here; see TestMultipartForeignUploadID.
func TestStaticAllowIgnoresOperation(t *testing.T) {
	t.Parallel()

	s := &s3auth.Static{AccessKey: "ak", SecretKey: "sk", Bucket: "vault"}
	p, ok, err := s.Lookup(context.Background(), "ak")
	require.NoError(t, err)
	require.True(t, ok)

	names := map[port.S3Op]string{
		port.S3OpGet:                     "get",
		port.S3OpHead:                    "head",
		port.S3OpPut:                     "put",
		port.S3OpDelete:                  "delete",
		port.S3OpList:                    "list",
		port.S3OpHeadBucket:              "head_bucket",
		port.S3OpListBuckets:             "list_buckets",
		port.S3OpCreateMultipartUpload:   "create_multipart",
		port.S3OpUploadPart:              "upload_part",
		port.S3OpCompleteMultipartUpload: "complete_multipart",
		port.S3OpAbortMultipartUpload:    "abort_multipart",
		port.S3OpListParts:               "list_parts",
	}
	for op := range names {
		t.Run(names[op], func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, s.Allow(context.Background(), p, op, "vault", "a"),
				"the v1 identity authorises on the bucket, not on the operation")
		})
	}
}
