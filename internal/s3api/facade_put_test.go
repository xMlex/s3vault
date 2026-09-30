package s3api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/cache"
	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/adapter/s3auth"
	"github.com/xMlex/s3vault/internal/adapter/scanner"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/s3api"
	"github.com/xMlex/s3vault/internal/service"
)

// countingStore counts real writes to the backend, so a test can prove that an
// identical PUT does not cost a backend Put (the gateway's intended saving).
type countingStore struct {
	*memStore
	puts int
}

func (c *countingStore) Put(ctx context.Context, key string, r io.Reader, m domain.PutMeta) error {
	c.puts++
	return c.memStore.Put(ctx, key, r, m)
}

type facade struct {
	api    *s3api.API
	store  *countingStore
	client *s3.Client
}

func (f *facade) puts() int { return f.store.puts }

// newFacade builds the S3 facade over a counting in-memory store. softTTL is the
// gateway's stale-while-revalidate window; 0 means "revalidate on every hit".
func newFacade(t *testing.T, softTTL time.Duration) *facade {
	t.Helper()

	store := &countingStore{memStore: newMemStore()}
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour, MaxBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	keys := keying.Mapper{Prefix: "backups"}
	fetch := service.NewFetch(store, encrypt.Passthrough{}).
		WithCache(disk, "vault", "fp").
		WithSoftTTL(softTTL)
	archive := service.NewArchive(scanner.New(scanner.Options{}), keys, store, encrypt.Passthrough{}, nil)

	api, err := s3api.New(s3api.Config{
		Identity:      &s3auth.Static{AccessKey: "AKIATEST", SecretKey: "secretsecretsecretsecret", Bucket: "vault"},
		Region:        "us-east-1",
		Bucket:        "vault",
		Fetch:         fetch,
		Archive:       archive,
		Keys:          keys,
		Store:         store,
		Cache:         disk,
		BucketBackend: "vault",
		EncFP:         "fp",
		Multipart:     s3api.MultipartConfig{Dir: t.TempDir()},
	})
	require.NoError(t, err)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	return &facade{
		api:   api,
		store: store,
		client: s3.New(s3.Options{
			BaseEndpoint: aws.String(srv.URL),
			Region:       "us-east-1",
			Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secretsecretsecretsecret", ""),
			UsePathStyle: true,
		}),
	}
}

func (f *facade) put(t *testing.T, key string, body []byte) {
	t.Helper()
	_, err := f.client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String(key),
		Body:   bytes.NewReader(body),
	})
	require.NoError(t, err)
}

func (f *facade) get(t *testing.T, key string) []byte {
	t.Helper()
	out, err := f.client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String(key),
	})
	require.NoError(t, err)
	defer func() { _ = out.Body.Close() }()
	b, err := io.ReadAll(out.Body)
	require.NoError(t, err)
	return b
}

// TestFacadePutScenarios pins the three intended gateway PUT outcomes:
//
//	A — key absent              → PUT to the backend, 200
//	B — key present, same hash  → no backend Put, 200 (the intended saving)
//	C — key present, hash differs → PUT to the backend, 200
//
// Decide has no policy parameter: there is no archive.on_change any more, so a
// differing upload is always written (docs/reliability-review.md H2). soft_ttl=0
// keeps the read-back out of the cache window; the window itself is covered by
// TestFacadePutDoesNotInvalidateCache.
func TestFacadePutScenarios(t *testing.T) {
	t.Parallel()

	f := newFacade(t, 0)

	first := []byte("version-one")
	second := []byte("version-two")

	// A: absent key → one backend Put.
	f.put(t, "k.bin", first)
	assert.Equal(t, 1, f.puts(), "scenario A must write to the backend")
	assert.Equal(t, first, f.get(t, "k.bin"))

	// B: same bytes → no backend Put (the intended saving).
	f.put(t, "k.bin", first)
	assert.Equal(t, 1, f.puts(), "scenario B must not write to the backend again")

	// C: different bytes → backend Put, new content served.
	f.put(t, "k.bin", second)
	assert.Equal(t, 2, f.puts(), "scenario C must overwrite in the backend")
	assert.Equal(t, second, f.get(t, "k.bin"))

	sum := sha256.Sum256(second)
	head, err := f.client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("k.bin"),
	})
	require.NoError(t, err)
	assert.Equal(t, `"`+hex.EncodeToString(sum[:])+`"`, aws.ToString(head.ETag))
	assert.Equal(t, int64(len(second)), aws.ToInt64(head.ContentLength))
}

// TestFacadePutDoesNotInvalidateCache reproduces a read-after-write violation:
// the gateway's plaintext cache is dropped on DeleteObject (s3api/delete.go) but
// not on PutObject, so a GET inside the soft_ttl window is served the previous
// version of the object.
func TestFacadePutDoesNotInvalidateCache(t *testing.T) {
	t.Parallel()

	f := newFacade(t, time.Minute)

	f.put(t, "k.bin", []byte("version-one"))
	assert.Equal(t, []byte("version-one"), f.get(t, "k.bin"), "warm the plaintext cache")

	f.put(t, "k.bin", []byte("version-two"))

	assert.Equal(t, []byte("version-two"), f.get(t, "k.bin"),
		"a read after a successful PUT must return the new version")

	head, err := f.client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("k.bin"),
	})
	require.NoError(t, err)
	sum := sha256.Sum256([]byte("version-two"))
	assert.Equal(t, `"`+hex.EncodeToString(sum[:])+`"`, aws.ToString(head.ETag),
		"HEAD after a successful PUT must expose the new ETag")
}
