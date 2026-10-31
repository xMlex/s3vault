package s3api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/adapter/s3auth"
	"github.com/xMlex/s3vault/internal/adapter/scanner"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/s3api"
	"github.com/xMlex/s3vault/internal/service"
)

// newTestAPINoCache builds the facade without the plaintext cache, i.e. the
// default deployment: every read goes to the store.
func newTestAPINoCache(t *testing.T, bucket string) (*s3api.API, *memStore) {
	t.Helper()

	store := newMemStore()
	fetch := service.NewFetch(store, encrypt.Passthrough{}).WithSpoolDir(t.TempDir())
	archive := service.NewArchive(
		scanner.New(scanner.Options{}),
		keying.Mapper{Prefix: mpKeyPrefix},
		store,
		encrypt.Passthrough{},
		nil,
	)

	api, err := s3api.New(s3api.Config{
		Identity: &s3auth.Static{
			AccessKey: mpAccessKey,
			SecretKey: mpSecretKey,
			Bucket:    bucket,
		},
		Region:        mpRegion,
		Bucket:        bucket,
		Fetch:         fetch,
		Archive:       archive,
		Keys:          keying.Mapper{Prefix: mpKeyPrefix},
		Store:         store,
		BucketBackend: bucket,
		EncFP:         "fp",
		Multipart:     s3api.MultipartConfig{Dir: t.TempDir()},
	})
	require.NoError(t, err)

	return api, store
}

func newSDKClient(t *testing.T, api *s3api.API) *s3.Client {
	t.Helper()

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	return s3.New(s3.Options{
		BaseEndpoint: aws.String(srv.URL),
		Region:       mpRegion,
		Credentials:  credentials.NewStaticCredentialsProvider(mpAccessKey, mpSecretKey, ""),
		UsePathStyle: true,
	})
}

// A HEAD is answered from metadata: the body of a large object is never read.
func TestHeadObjectDoesNotReadBody(t *testing.T) {
	t.Parallel()

	api, store := newTestAPINoCache(t, "vault")
	client := newSDKClient(t, api)

	payload := bytes.Repeat([]byte("head-body-"), 512<<10) // 5 MiB
	sum := sha256.Sum256(payload)

	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("docs/big.bin"),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err)

	store.mu.Lock()
	store.gets, store.rangeBytes = 0, 0
	store.mu.Unlock()

	head, err := client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("docs/big.bin"),
	})
	require.NoError(t, err)
	assert.Equal(t, int64(len(payload)), aws.ToInt64(head.ContentLength))
	assert.Equal(t, `"`+hex.EncodeToString(sum[:])+`"`, aws.ToString(head.ETag))

	store.mu.Lock()
	gets, rangeBytes := store.gets, store.rangeBytes
	store.mu.Unlock()

	assert.Zero(t, gets, "HEAD must not download the object")
	assert.LessOrEqual(t, rangeBytes, int64(128), "HEAD reads at most the container header")
}

// A ranged GET fetches the window around the range, not the whole object.
func TestRangedGetReadsOnlyRange(t *testing.T) {
	t.Parallel()

	api, store := newTestAPINoCache(t, "vault")
	client := newSDKClient(t, api)

	payload := make([]byte, 5<<20)
	for i := range payload {
		payload[i] = byte(i * 11)
	}

	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("docs/big.bin"),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err)

	store.mu.Lock()
	store.gets, store.rangeBytes = 0, 0
	store.mu.Unlock()

	const (
		at     = int64(2<<20) + 123
		length = 4096
	)

	got, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("docs/big.bin"),
		Range:  aws.String("bytes=" + strconv.FormatInt(at, 10) + "-" + strconv.FormatInt(at+length-1, 10)),
	})
	require.NoError(t, err)

	defer func() { _ = got.Body.Close() }()

	body, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	assert.Equal(t, payload[at:at+length], body)

	store.mu.Lock()
	gets, rangeBytes := store.gets, store.rangeBytes
	store.mu.Unlock()

	assert.Zero(t, gets, "a ranged GET must not download the whole object")
	assert.Less(t, rangeBytes, int64(2<<20), "one range window, not the 5 MiB object")
}
