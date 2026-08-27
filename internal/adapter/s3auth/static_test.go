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
