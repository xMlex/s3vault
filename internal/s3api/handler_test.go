package s3api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/cache"
	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/adapter/s3auth"
	"github.com/xMlex/s3vault/internal/adapter/scanner"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
	"github.com/xMlex/s3vault/internal/service"
)

type memStore struct {
	mu   sync.Mutex
	meta map[string]domain.ObjectMeta
	body map[string][]byte
}

func newMemStore() *memStore {
	return &memStore{meta: map[string]domain.ObjectMeta{}, body: map[string][]byte{}}
}

func (m *memStore) Head(_ context.Context, key string) (domain.ObjectMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	meta, ok := m.meta[key]
	if !ok {
		return domain.ObjectMeta{Key: key, Exists: false}, nil
	}
	return meta, nil
}

// Put models the real store contract for identity: a container carries it in the
// body header, a containerless object in PutMeta (the S3 adapter persists it as
// user-metadata, the local store derives it from the file).
func (m *memStore) Put(_ context.Context, key string, r io.Reader, meta domain.PutMeta) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	om := domain.ObjectMeta{
		Key:          key,
		Exists:       true,
		Size:         int64(len(b)),
		ETag:         `"etag-` + key + `"`,
		LastModified: time.Unix(1_700_000_000, 0).UTC(),
	}
	switch {
	case meta.PlaintextSHA256 != "":
		om.SHA256 = meta.PlaintextSHA256
		om.ContentSize = meta.PlaintextSize
	case len(b) >= container.HeaderSize && container.IsMagic(b):
		if hdr, err := container.Parse(b[:container.HeaderSize]); err == nil {
			om.SHA256 = hdr.SHA256Hex()
			om.ContentSize = hdr.PlaintextSize
			om.Encrypted = container.EncName(hdr.Enc)
			om.Wrap = container.WrapName(hdr.Wrap)
			om.Provider = hdr.Provider
			om.FormatVersion = container.FormatVersion
			om.CryptoProThumbprint = hdr.ThumbprintHex()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.body[key] = b
	m.meta[key] = om
	return nil
}

func (m *memStore) Get(_ context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.body[key]
	if !ok {
		return nil, domain.ObjectMeta{}, domain.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(b)), m.meta[key], nil
}

func (m *memStore) GetRange(_ context.Context, key string, start, end int64) (io.ReadCloser, domain.ObjectMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.body[key]
	if !ok {
		return nil, domain.ObjectMeta{}, domain.ErrNotFound
	}
	if start < 0 || end < start {
		return nil, domain.ObjectMeta{}, fmt.Errorf("invalid range")
	}
	if start >= int64(len(b)) {
		return io.NopCloser(bytes.NewReader(nil)), m.meta[key], nil
	}
	to := end + 1
	if to > int64(len(b)) {
		to = int64(len(b))
	}
	return io.NopCloser(bytes.NewReader(b[start:to])), m.meta[key], nil
}

func (m *memStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.body, key)
	delete(m.meta, key)
	return nil
}

func (m *memStore) List(_ context.Context, opts domain.ListOptions) (domain.ListPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var contents []domain.ListObject
	for key, meta := range m.meta {
		if opts.Prefix != "" && !strings.HasPrefix(key, opts.Prefix) {
			continue
		}
		contents = append(contents, domain.ListObject{
			Key:          key,
			Size:         meta.Size,
			ETag:         meta.ETag,
			LastModified: meta.LastModified,
		})
	}
	return domain.ListPage{Contents: contents, KeyCount: int32(len(contents))}, nil
}

func TestAllowWrongBucket(t *testing.T) {
	t.Parallel()
	id := &s3auth.Static{
		AccessKey: "AKIATEST",
		SecretKey: "secretsecretsecretsecret",
		Bucket:    "vault",
	}
	err := id.Allow(context.Background(), port.Principal{
		AccessKeyID:    "AKIATEST",
		AllowedBuckets: []string{"vault"},
	}, port.S3OpGet, "other", "key")
	require.ErrorIs(t, err, port.ErrAccessDenied)
}

func TestRoutingReservedBucket(t *testing.T) {
	t.Parallel()
	api, cleanup := newTestAPI(t, "vault")
	t.Cleanup(cleanup)

	req := httptest.NewRequest(http.MethodGet, "/files/x", nil)
	rr := httptest.NewRecorder()
	api.Handler().ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), string(s3err.InvalidBucketName))
}

func TestSDKPutHeadGet(t *testing.T) {
	t.Parallel()
	api, cleanup := newTestAPI(t, "vault")
	t.Cleanup(cleanup)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(srv.URL),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secretsecretsecretsecret", ""),
		UsePathStyle: true,
	})

	payload := []byte("hello-s3api")
	sum := sha256.Sum256(payload)
	wantETag := `"` + hex.EncodeToString(sum[:]) + `"`
	wantChecksum := base64.StdEncoding.EncodeToString(sum[:])

	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("docs/a.txt"),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err)

	head, err := client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("docs/a.txt"),
	})
	require.NoError(t, err)
	assert.Equal(t, wantETag, aws.ToString(head.ETag))
	assert.Equal(t, wantChecksum, aws.ToString(head.ChecksumSHA256))
	assert.Equal(t, types.ChecksumTypeFullObject, head.ChecksumType)

	got, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("docs/a.txt"),
	})
	require.NoError(t, err)
	defer got.Body.Close()
	body, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, body)
	assert.Equal(t, wantETag, aws.ToString(got.ETag))
	assert.Equal(t, wantChecksum, aws.ToString(got.ChecksumSHA256))
	assert.Equal(t, types.ChecksumTypeFullObject, got.ChecksumType)
}

func TestListBucketsXML(t *testing.T) {
	t.Parallel()
	api, cleanup := newTestAPI(t, "vault")
	t.Cleanup(cleanup)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(srv.URL),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secretsecretsecretsecret", ""),
		UsePathStyle: true,
	})
	out, err := client.ListBuckets(context.Background(), &s3.ListBucketsInput{})
	require.NoError(t, err)
	require.Len(t, out.Buckets, 1)
	assert.Equal(t, "vault", aws.ToString(out.Buckets[0].Name))
}

func TestAccessDeniedWrongBucketViaHTTP(t *testing.T) {
	t.Parallel()
	api, cleanup := newTestAPI(t, "vault")
	t.Cleanup(cleanup)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(srv.URL),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secretsecretsecretsecret", ""),
		UsePathStyle: true,
	})
	_, err := client.HeadBucket(context.Background(), &s3.HeadBucketInput{
		Bucket: aws.String("wrong"),
	})
	require.Error(t, err)

	_, err = client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: aws.String("wrong"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
}

func TestBucketAsPrefixUsesBucketInKey(t *testing.T) {
	t.Parallel()
	api, cleanup := newTestAPIWith(t, "vault", true)
	t.Cleanup(cleanup)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(srv.URL),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secretsecretsecretsecret", ""),
		UsePathStyle: true,
	})

	_, err := client.HeadBucket(context.Background(), &s3.HeadBucketInput{
		Bucket: aws.String("reports"),
	})
	require.NoError(t, err)

	payload := []byte("hello-bucket-as-prefix")
	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("reports"),
		Key:    aws.String("docs/b.txt"),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err)

	got, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String("reports"),
		Key:    aws.String("docs/b.txt"),
	})
	require.NoError(t, err)
	defer got.Body.Close()
	body, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	assert.Equal(t, payload, body)

	// Different client bucket → different key prefix → miss
	_, err = client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String("other"),
		Key:    aws.String("docs/b.txt"),
	})
	require.Error(t, err)

	list, err := client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: aws.String("reports"),
	})
	require.NoError(t, err)
	assert.Equal(t, "reports", aws.ToString(list.Name))
	require.Len(t, list.Contents, 1)
	assert.Equal(t, "docs/b.txt", aws.ToString(list.Contents[0].Key))
}

func TestErrorXMLShape(t *testing.T) {
	t.Parallel()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/vault/missing", nil)
	s3err.WriteError(rr, req, s3err.NoSuchKey, "")
	assert.Equal(t, http.StatusNotFound, rr.Code)
	var doc s3err.Error
	require.NoError(t, xml.Unmarshal(rr.Body.Bytes(), &doc))
	assert.Equal(t, "NoSuchKey", doc.Code)
	assert.NotEmpty(t, doc.RequestID)
}

func newTestAPI(t *testing.T, bucket string) (*s3api.API, func()) {
	t.Helper()
	return newTestAPIWith(t, bucket, false)
}

func newTestAPIWith(t *testing.T, bucket string, bucketAsPrefix bool) (*s3api.API, func()) {
	t.Helper()
	api, _, cleanup := newTestAPIStore(t, bucket, bucketAsPrefix)
	return api, cleanup
}

func newTestAPIStore(t *testing.T, bucket string, bucketAsPrefix bool) (*s3api.API, *memStore, func()) {
	t.Helper()
	store := newMemStore()
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour, MaxBytes: 1 << 20})
	require.NoError(t, err)
	fetch := service.NewFetch(store, encrypt.Passthrough{}).
		WithCache(disk, bucket, "fp").
		WithSoftTTL(time.Minute)
	archive := service.NewArchive(
		scanner.New(scanner.Options{}),
		keying.Mapper{Prefix: "backups"},
		store,
		encrypt.Passthrough{},
		nil,
	)
	idBucket := bucket
	if bucketAsPrefix {
		idBucket = ""
	}
	api, err := s3api.New(s3api.Config{
		Identity: &s3auth.Static{
			AccessKey: "AKIATEST",
			SecretKey: "secretsecretsecretsecret",
			Bucket:    idBucket,
		},
		Region:         "us-east-1",
		Bucket:         bucket,
		Fetch:          fetch,
		Archive:        archive,
		Keys:           keying.Mapper{Prefix: "backups"},
		Store:          store,
		Cache:          disk,
		BucketBackend:  bucket,
		BucketAsPrefix: bucketAsPrefix,
		EncFP:          "fp",
		Multipart:      s3api.MultipartConfig{Dir: t.TempDir()},
	})
	require.NoError(t, err)
	return api, store, func() { _ = disk.Close() }
}

// A ranged response must not carry the whole object's checksum.
//
// x-amz-checksum-sha256 describes the bytes in the body, and a 206 body is a
// range. Advertising the whole object's digest there is a false claim, and
// clients that verify checksums act on it: `aws s3 cp` downloads large objects
// in ranges and fails the whole transfer with "Expected checksum ... did not
// match". This was reachable only for objects over 5 MiB, because below that the
// gateway could not accept an upload at all — multipart is what exposed it.
func TestRangedGetOmitsWholeObjectChecksum(t *testing.T) {
	t.Parallel()
	api, cleanup := newTestAPI(t, "vault")
	t.Cleanup(cleanup)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(srv.URL),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secretsecretsecretsecret", ""),
		UsePathStyle: true,
	})

	payload := []byte(strings.Repeat("0123456789abcdef", 64)) // 1 KiB
	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("range.bin"),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err)

	sum := sha256.Sum256(payload)
	wantWhole := base64.StdEncoding.EncodeToString(sum[:])

	t.Run("whole object advertises its digest", func(t *testing.T) {
		t.Parallel()

		got, err := client.GetObject(context.Background(), &s3.GetObjectInput{
			Bucket: aws.String("vault"),
			Key:    aws.String("range.bin"),
		})
		require.NoError(t, err)

		defer func() { _ = got.Body.Close() }()

		assert.Equal(t, wantWhole, aws.ToString(got.ChecksumSHA256))
		assert.Equal(t, types.ChecksumTypeFullObject, got.ChecksumType)
	})

	t.Run("range advertises nothing", func(t *testing.T) {
		t.Parallel()

		got, err := client.GetObject(context.Background(), &s3.GetObjectInput{
			Bucket: aws.String("vault"),
			Key:    aws.String("range.bin"),
			Range:  aws.String("bytes=0-15"),
		})
		require.NoError(t, err)

		defer func() { _ = got.Body.Close() }()

		body, err := io.ReadAll(got.Body)
		require.NoError(t, err)
		assert.Equal(t, payload[:16], body)
		assert.Empty(t, aws.ToString(got.ChecksumSHA256),
			"a 206 must not claim the whole object's digest")
		assert.Empty(t, got.ChecksumType)
	})
}

// A raw/legacy object has no container SHA-256 and carries a pre-quoted ETag;
// the facade must still emit a single, valid ETag and no checksum header.
func TestSDKHeadValidETagWithoutContainer(t *testing.T) {
	t.Parallel()
	api, store, cleanup := newTestAPIStore(t, "vault", false)
	t.Cleanup(cleanup)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	const quoted = `"c-18d60b88a89c5eea"`
	store.mu.Lock()
	store.body["backups/docs/raw.txt"] = []byte("raw-plaintext")
	store.meta["backups/docs/raw.txt"] = domain.ObjectMeta{
		Key:          "backups/docs/raw.txt",
		Exists:       true,
		Size:         int64(len("raw-plaintext")),
		ETag:         quoted,
		LastModified: time.Unix(1_700_000_000, 0).UTC(),
	}
	store.mu.Unlock()

	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(srv.URL),
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIATEST", "secretsecretsecretsecret", ""),
		UsePathStyle: true,
	})

	head, err := client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("docs/raw.txt"),
	})
	require.NoError(t, err)
	assert.Equal(t, quoted, aws.ToString(head.ETag))
	assert.Empty(t, aws.ToString(head.ChecksumSHA256))

	got, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String("vault"),
		Key:    aws.String("docs/raw.txt"),
	})
	require.NoError(t, err)
	defer func() { _ = got.Body.Close() }()
	assert.Equal(t, quoted, aws.ToString(got.ETag))
	assert.Empty(t, aws.ToString(got.ChecksumSHA256))
	body, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	assert.Equal(t, "raw-plaintext", string(body))
}
