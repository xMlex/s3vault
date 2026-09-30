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
// docs/reliability-review.md: the audit states that when the PUT body is itself
// an S3VCTR01 container (the S3 client is another s3vault), the facade hashes
// the container but compares it against the plaintext SHA, so PUT and GET
// disagree and Decide can silently skip. In the current tree the facade's object
// identity is uniformly the *received body*: the same quantity is stored,
// compared and served. PUT/HEAD/GET agree; GET returns exactly what was sent.
//
// This test would fail if the facade started taking its identity from the inner
// client container while still storing/serving the outer bytes, or vice versa.
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

	// The request body is a full client layer: S3VCTR01 || inner-plaintext.
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
	wantETag := `"` + hex.EncodeToString(bodySum[:]) + `"`

	put, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("h1.bin"),
		Body:   bytes.NewReader(body),
	})
	require.NoError(t, err)

	// Stored identity is the received body, not the inner plaintext. The facade
	// therefore compares like with like in Decide (no cross-type SHA compare).
	meta := store.meta["backups/h1.bin"]
	assert.Equal(t, hex.EncodeToString(bodySum[:]), meta.SHA256, "identity must be the received body")
	assert.Equal(t, int64(len(body)), meta.ContentSize, "plaintext size must be the received body size")

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
