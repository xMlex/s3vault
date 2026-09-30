package s3api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/container"
)

// TestFacadeIdentityIsReceivedBody pins down the H1 claim from
// docs/reliability-review.md: the facade must not hash the container and compare
// it against the plaintext SHA, which would make PUT and GET disagree and let
// Decide silently skip. Identity is uniformly the *received body*: the same
// quantity is stored, compared and served.
//
// With encryption.mode=none the client sends the bare payload, so there is
// nothing to disagree about and GET returns exactly what was sent.
func TestFacadeIdentityIsReceivedBody(t *testing.T) {
	t.Parallel()

	api, store, cleanup := newTestAPIStore(t, "vault", false)
	t.Cleanup(cleanup)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(srv.URL),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secretsecretsecretsecret", ""),
		UsePathStyle: true,
	})

	// encryption.mode=none writes the bare payload, digest declared in PutMeta.
	body := []byte("hello-plaintext")
	bodySum := sha256.Sum256(body)
	wantETag := `"` + hex.EncodeToString(bodySum[:]) + `"`

	put, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("h1.bin"),
		Body:   bytes.NewReader(body),
	})
	require.NoError(t, err)

	// Stored identity is the received body, not some inner plaintext.
	meta := store.meta["backups/h1.bin"]
	assert.Equal(t, hex.EncodeToString(bodySum[:]), meta.SHA256, "identity must be the received body")
	assert.Equal(t, int64(len(body)), meta.ContentSize)

	// H1 claims PUT and GET disagree on ETag. They do not.
	assert.Equal(t, wantETag, aws.ToString(put.ETag))

	head, err := client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("h1.bin"),
	})
	require.NoError(t, err)
	assert.Equal(t, wantETag, aws.ToString(head.ETag))

	got, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("h1.bin"),
	})
	require.NoError(t, err)

	defer func() { _ = got.Body.Close() }()

	gotBody, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	assert.Equal(t, wantETag, aws.ToString(got.ETag))
	assert.True(t, bytes.Equal(body, gotBody), "GET must return exactly the PUT body")
}

// A PUT body that is itself a full client layer is stored verbatim: the facade is
// not that layer's owner, so it neither adds nor removes one on the way in.
// Identity and payload are two different quantities here, and neither is taken
// from the other.
func TestFacadeStoresClientLayerVerbatim(t *testing.T) {
	t.Parallel()

	api, store, cleanup := newTestAPIStore(t, "vault", false)
	t.Cleanup(cleanup)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(srv.URL),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secretsecretsecretsecret", ""),
		UsePathStyle: true,
	})

	innerPlain := []byte("hello-plaintext")
	innerSum := sha256.Sum256(innerPlain)
	innerHdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: int64(len(innerPlain)),
		SHA256:        innerSum[:],
		Enc:           container.EncNone,
	})
	require.NoError(t, err)

	body := append(append([]byte(nil), innerHdr...), innerPlain...)

	bodySum := sha256.Sum256(body)

	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("h2.bin"),
		Body:   bytes.NewReader(body),
	})
	require.NoError(t, err)

	assert.Equal(t, body, store.body["backups/h2.bin"], "stored bytes are the received bytes")
	assert.Equal(t, hex.EncodeToString(bodySum[:]), store.meta["backups/h2.bin"].SHA256)

	// On egress the facade removes one layer — the container declares enc=none,
	// the mode it is configured for — and serves what is inside it.
	got, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("h2.bin"),
	})
	require.NoError(t, err)

	defer func() { _ = got.Body.Close() }()

	gotBody, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	assert.Equal(t, innerPlain, gotBody, "exactly one layer removed on egress")
}
