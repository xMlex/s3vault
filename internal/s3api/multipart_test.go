package s3api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/cache"
	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/adapter/s3auth"
	"github.com/xMlex/s3vault/internal/adapter/scanner"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
	"github.com/xMlex/s3vault/internal/service"
)

// partSize is 5 MiB — the AWS SDK uploader's own boundary
// (manager.DefaultUploadPartSize == MinUploadPartSize). It is the reason this
// whole feature exists, so the tests use the real value rather than something
// small: with tiny parts none of them would have failed with 405.
const partSize = int64(5 << 20)

const (
	mpAccessKey = "AKIATEST"
	mpSecretKey = "secretsecretsecretsecret"
	mpBucket    = "vault"
	mpKeyPrefix = "backups"
	mpRegion    = "us-east-1"
)

// mpFacade is a gateway S3 facade plus what a multipart test needs: the
// in-memory storage behind it, a SigV4 client, and the spool directory it can
// assert is empty.
type mpFacade struct {
	api     *s3api.API
	store   *memStore
	client  *s3.Client
	spool   string
	keys    keying.Mapper
	baseURL string
}

// newMPFacade builds a gateway that frames (it is a hop) over Passthrough
// encryption, and returns it. ttl is the session TTL, so a test that exercises
// expiry can ask for a short one instead of sleeping an hour.
func newMPFacade(t *testing.T, ttl time.Duration, opts ...func(*s3api.MultipartConfig)) *mpFacade {
	t.Helper()

	store := newMemStore()
	// The cache must be able to hold a whole multipart object: an entry larger
	// than max_bytes is evicted the moment it is populated, and the read that
	// follows would then fail on a missing file.
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour, MaxBytes: 64 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	mp := s3api.MultipartConfig{Dir: t.TempDir(), TTL: ttl, MaxSessions: 8}
	for _, o := range opts {
		o(&mp)
	}

	keys := keying.Mapper{Prefix: mpKeyPrefix}
	// WithFraming(true) is what the `server` command sets: the gateway is a hop,
	// so it frames even at encryption.mode=none.
	archive := service.NewArchive(scanner.New(scanner.Options{}), keys, store, encrypt.Passthrough{}, nil).
		WithFraming(true)

	api, err := s3api.New(s3api.Config{
		Identity:      &s3auth.Static{AccessKey: mpAccessKey, SecretKey: mpSecretKey, Bucket: mpBucket},
		Region:        mpRegion,
		Bucket:        mpBucket,
		Fetch:         service.NewFetch(store, encrypt.Passthrough{}).WithCache(disk, mpBucket, "fp"),
		Archive:       archive,
		Keys:          keys,
		Store:         store,
		Cache:         disk,
		BucketBackend: mpBucket,
		EncFP:         "fp",
		Multipart:     mp,
	})
	require.NoError(t, err)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	return &mpFacade{
		api: api, store: store, spool: mp.Dir, keys: keys, baseURL: srv.URL,
		client: newS3Client(srv.URL, mpAccessKey, mpSecretKey),
	}
}

func newS3Client(endpoint, ak, sk string) *s3.Client {
	return s3.New(s3.Options{
		BaseEndpoint: aws.String(endpoint),
		Region:       mpRegion,
		Credentials:  credentials.NewStaticCredentialsProvider(ak, sk, ""),
		UsePathStyle: true,
	})
}

// uploaded returns the bytes a store Put landed for a client key.
func (f *mpFacade) uploaded(t *testing.T, clientKey string) []byte {
	t.Helper()

	key, err := f.keys.FromRequestPath(clientKey)
	require.NoError(t, err)
	f.store.mu.Lock()
	defer f.store.mu.Unlock()

	b, ok := f.store.body[key]
	require.True(t, ok, "nothing was written for %s", key)

	return b
}

// createUpload opens a multipart session through the SDK.
func (f *mpFacade) createUpload(t *testing.T, key string) string {
	t.Helper()

	out, err := f.client.CreateMultipartUpload(context.Background(), &s3.CreateMultipartUploadInput{
		Bucket: aws.String(mpBucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err)
	require.NotEmpty(t, aws.ToString(out.UploadId))

	return aws.ToString(out.UploadId)
}

// uploadPart sends one part and returns the ETag the gateway reported.
func (f *mpFacade) uploadPart(t *testing.T, key, uploadID string, n int32, body []byte) string {
	t.Helper()

	out, err := f.client.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:     aws.String(mpBucket),
		Key:        aws.String(key),
		PartNumber: aws.Int32(n),
		UploadId:   aws.String(uploadID),
		Body:       bytes.NewReader(body),
	})
	require.NoError(t, err)

	return aws.ToString(out.ETag)
}

// complete finishes an upload with the given part list.
func (f *mpFacade) complete(t *testing.T, key, uploadID string, parts []types.CompletedPart) (*s3.CompleteMultipartUploadOutput, error) {
	t.Helper()

	return f.client.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(mpBucket),
		Key:             aws.String(key),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
}

// read returns the object the client sees through the facade.
func (f *mpFacade) read(t *testing.T, key string) []byte {
	t.Helper()

	got, err := f.client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(mpBucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err)

	defer func() { _ = got.Body.Close() }()

	body, err := io.ReadAll(got.Body)
	require.NoError(t, err)

	return body
}

func completed(n int32, etag string) types.CompletedPart {
	return types.CompletedPart{PartNumber: aws.Int32(n), ETag: aws.String(etag)}
}

// apiErrCode digs the S3 error code out of a smithy API error, which is what a
// client acts on.
func apiErrCode(t *testing.T, err error) string {
	t.Helper()
	require.Error(t, err)

	var api interface{ ErrorCode() string }
	require.ErrorAs(t, err, &api)

	return api.ErrorCode()
}

// TestMultipartRoundtripThroughSDKUploader is the case the plan was written for:
// the AWS SDK uploader sees more than 5 MiB and switches to multipart, and until
// the gateway implemented it the facade answered 405 MethodNotAllowed at the
// router — before SigV4, before the storage. The client must read back exactly
// what it wrote.
func TestMultipartRoundtripThroughSDKUploader(t *testing.T) {
	t.Parallel()

	f := newMPFacade(t, time.Hour)
	payload := patternBytes(12<<20 + 7)

	up := manager.NewUploader(f.client)                           //nolint:staticcheck // the uploader s3vault itself uses, on purpose
	_, err := up.Upload(context.Background(), &s3.PutObjectInput{ //nolint:staticcheck // see above
		Bucket: aws.String(mpBucket),
		Key:    aws.String("big/pipe.bin"),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err, "an upload over 5 MiB must not fail with 405")

	assert.Equal(t, payload, f.read(t, "big/pipe.bin"),
		"the object the client reads back must be the object it wrote")

	sum := sha256.Sum256(payload)
	assert.Equal(t, `"`+hex.EncodeToString(sum[:])+`"`, aws.ToString(
		mustHead(t, f, "big/pipe.bin").ETag,
	),
		"the assembled ETag is sha256(plaintext), the same scheme Get and Put report")
}

// TestMultipartWritesOneObjectWithOneGatewayLayer pins the layer invariant from
// docs/multipart.md §6: parts are assembled *before* the gateway frames, so the
// storage holds exactly one S3VCTR01 container — the gateway's own. If assembly
// happened after the frame, the client would find two containers on the way back
// and strip the wrong one.
func TestMultipartWritesOneObjectWithOneGatewayLayer(t *testing.T) {
	t.Parallel()

	f := newMPFacade(t, time.Hour)

	const key = "layered/bin.dat"

	first := patternBytes(partSize)
	second := patternBytes(1024)

	uploadID := f.createUpload(t, key)
	e1 := f.uploadPart(t, key, uploadID, 1, first)
	e2 := f.uploadPart(t, key, uploadID, 2, second)
	_, err := f.complete(t, key, uploadID, []types.CompletedPart{completed(1, e1), completed(2, e2)})
	require.NoError(t, err)

	stored := f.uploaded(t, key)
	assert.True(t, container.IsMagic(stored), "the gateway frames even at encryption.mode=none")
	assert.Equal(t, int64(len(first)+len(second)), int64(len(stored))-container.HeaderSize,
		"the payload is the concatenation of the parts and nothing else")

	hdr, err := container.Parse(stored[:container.HeaderSize])
	require.NoError(t, err)

	want := sha256.New()
	_, _ = want.Write(first)
	_, _ = want.Write(second)
	assert.Equal(t, hex.EncodeToString(want.Sum(nil)), hdr.SHA256Hex(),
		"the container carries the digest of the assembled plaintext, not of a part")
	assert.Equal(t, int64(len(first)+len(second)), hdr.PlaintextSize)

	// One layer, and it is the gateway's: reading the object back yields the
	// plaintext, not a second container.
	assert.Equal(t, append(append([]byte{}, first...), second...), f.read(t, key))
}

// TestMultipartAssemblesInPartNumberOrderNotArrivalOrder pins that the gateway
// honours the client's part list, not the order the files arrived in. The SDK
// uploads five parts concurrently, so arrival order is arbitrary by design.
func TestMultipartAssemblesInPartNumberOrderNotArrivalOrder(t *testing.T) {
	t.Parallel()

	f := newMPFacade(t, time.Hour)

	const key = "order/tri.bin"

	// All three parts are 5 MiB so the S3 minimum-size rule applies to parts 1
	// and 2 and the test exercises ordering rather than the size check.
	parts := [][]byte{patternBytes(partSize), patternBytes(partSize), patternBytes(partSize)}
	for i := range parts {
		for j := range parts[i] {
			parts[i][j] += byte(i)
		}
	}

	uploadID := f.createUpload(t, key)
	etags := make([]string, len(parts))
	// Deliberately out of order: 3, 1, 2.
	for _, i := range []int32{3, 1, 2} {
		etags[i-1] = f.uploadPart(t, key, uploadID, i, parts[i-1])
	}

	_, err := f.complete(t, key, uploadID, []types.CompletedPart{
		completed(1, etags[0]), completed(2, etags[1]), completed(3, etags[2]),
	})
	require.NoError(t, err)

	var want []byte
	for _, p := range parts {
		want = append(want, p...)
	}

	assert.Equal(t, want, f.read(t, key))
}

// TestMultipartCompleteRejections covers the completion lists a client can send
// that do not describe the upload. Each names the actual number so a client can
// act on it, rather than the bare InternalError a missing code would produce.
func TestMultipartCompleteRejections(t *testing.T) {
	t.Parallel()

	const key = "reject/x.bin"

	t.Run("etag mismatch is InvalidPart", func(t *testing.T) {
		t.Parallel()
		f := newMPFacade(t, time.Hour)
		uploadID := f.createUpload(t, key)
		stored := f.uploadPart(t, key, uploadID, 1, []byte("body"))
		_, err := f.complete(t, key, uploadID, []types.CompletedPart{completed(1, `"deadbeef"`)})
		assert.Equal(t, string(s3err.InvalidPart), apiErrCode(t, err))
		assert.Contains(t, err.Error(), strings.Trim(stored, `"`),
			"the message names the ETag that was actually stored")
	})

	t.Run("part that was never uploaded is InvalidPart", func(t *testing.T) {
		t.Parallel()
		f := newMPFacade(t, time.Hour)
		uploadID := f.createUpload(t, key)
		e1 := f.uploadPart(t, key, uploadID, 1, patternBytes(partSize))
		e3 := f.uploadPart(t, key, uploadID, 3, patternBytes(16))
		_, err := f.complete(t, key, uploadID, []types.CompletedPart{completed(1, e1), completed(2, `"nope"`), completed(3, e3)})
		assert.Equal(t, string(s3err.InvalidPart), apiErrCode(t, err))
		assert.Contains(t, err.Error(), "part 2")
	})

	t.Run("unlisted parts are discarded, as in S3", func(t *testing.T) {
		t.Parallel()
		f := newMPFacade(t, time.Hour)
		uploadID := f.createUpload(t, key)
		first := patternBytes(partSize)
		e1 := f.uploadPart(t, key, uploadID, 1, first)
		f.uploadPart(t, key, uploadID, 2, patternBytes(16))

		// S3 builds the object from the listed parts and throws the rest away.
		// A facade that answered InvalidPart here would reject a client that
		// real S3 accepts, and the client has no way to recover but to re-upload.
		_, err := f.complete(t, key, uploadID, []types.CompletedPart{completed(1, e1)})
		require.NoError(t, err)
		assert.Equal(t, first, f.read(t, key))
	})

	t.Run("descending parts is InvalidPartOrder", func(t *testing.T) {
		t.Parallel()
		f := newMPFacade(t, time.Hour)
		uploadID := f.createUpload(t, key)
		e1 := f.uploadPart(t, key, uploadID, 1, patternBytes(partSize))
		e2 := f.uploadPart(t, key, uploadID, 2, patternBytes(partSize))
		_, err := f.complete(t, key, uploadID, []types.CompletedPart{completed(2, e2), completed(1, e1)})
		assert.Equal(t, string(s3err.InvalidPartOrder), apiErrCode(t, err))
	})

	t.Run("short non-final part is EntityTooSmall", func(t *testing.T) {
		t.Parallel()
		f := newMPFacade(t, time.Hour)
		uploadID := f.createUpload(t, key)
		e1 := f.uploadPart(t, key, uploadID, 1, []byte("too small"))
		e2 := f.uploadPart(t, key, uploadID, 2, patternBytes(16))
		_, err := f.complete(t, key, uploadID, []types.CompletedPart{completed(1, e1), completed(2, e2)})
		assert.Equal(t, string(s3err.EntityTooSmall), apiErrCode(t, err))
		assert.Contains(t, err.Error(), strconv.FormatInt(partSize, 10), "the message names the limit")
	})

	t.Run("empty part list completes from every uploaded part", func(t *testing.T) {
		t.Parallel()
		f := newMPFacade(t, time.Hour)
		uploadID := f.createUpload(t, key)
		first := patternBytes(partSize)
		second := patternBytes(16)

		f.uploadPart(t, key, uploadID, 1, first)
		f.uploadPart(t, key, uploadID, 2, second)

		// An empty body is not a malformed request: aws-cli sends exactly this
		// when --multipart-upload is omitted, and S3 assembles from every part
		// that was uploaded. Rejecting it would turn away a working client.
		_, err := f.complete(t, key, uploadID, nil)
		require.NoError(t, err)
		assert.Equal(t, append(append([]byte{}, first...), second...), f.read(t, key))
	})

	t.Run("a rejected completion keeps the parts on disk", func(t *testing.T) {
		t.Parallel()
		f := newMPFacade(t, time.Hour)
		uploadID := f.createUpload(t, key)
		f.uploadPart(t, key, uploadID, 1, patternBytes(partSize))
		_, err := f.complete(t, key, uploadID, []types.CompletedPart{completed(1, `"deadbeef"`)})
		require.Error(t, err)

		// The session is still usable: a client can correct its ETag and retry
		// without re-sending 5 MiB. Removing parts before a successful upload
		// would turn a typo into a full re-upload.
		list, err := f.client.ListParts(context.Background(), &s3.ListPartsInput{
			Bucket:   aws.String(mpBucket),
			Key:      aws.String(key),
			UploadId: aws.String(uploadID),
		})
		require.NoError(t, err)
		require.Len(t, list.Parts, 1)
		assert.Equal(t, int32(1), aws.ToInt32(list.Parts[0].PartNumber))
		assert.Equal(t, partSize, aws.ToInt64(list.Parts[0].Size))
	})
}

// TestMultipartUnknownUploadID pins NoSuchUpload. Without it the client would
// see InternalError, and could not tell a permanent failure from a retryable one.
func TestMultipartUnknownUploadID(t *testing.T) {
	t.Parallel()

	f := newMPFacade(t, time.Hour)
	_, err := f.client.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:     aws.String(mpBucket),
		Key:        aws.String("gone/x.bin"),
		PartNumber: aws.Int32(1),
		UploadId:   aws.String(strings.Repeat("0", 64)),
		Body:       bytes.NewReader([]byte("x")),
	})
	assert.Equal(t, string(s3err.NoSuchUpload), apiErrCode(t, err))

	_, err = f.client.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(mpBucket),
		Key:      aws.String("gone/x.bin"),
		UploadId: aws.String(strings.Repeat("0", 64)),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{completed(1, `"whatever"`)},
		},
	})
	assert.Equal(t, string(s3err.NoSuchUpload), apiErrCode(t, err))
}

// TestMultipartForeignUploadID pins that an upload id is a capability bound to
// its creator, not a bare token. Two principals share one facade here — the shape
// s3auth.Static has today minus the second key — so the check has to live in the
// registry, not in Allow, or it stops holding as soon as Allow grows.
func TestMultipartForeignUploadID(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour, MaxBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	keys := keying.Mapper{Prefix: mpKeyPrefix}
	api, err := s3api.New(s3api.Config{
		Identity:      &twoPrincipalIdentity{bucket: mpBucket},
		Region:        mpRegion,
		Bucket:        mpBucket,
		Fetch:         service.NewFetch(store, encrypt.Passthrough{}).WithCache(disk, mpBucket, "fp"),
		Archive:       service.NewArchive(scanner.New(scanner.Options{}), keys, store, encrypt.Passthrough{}, nil).WithFraming(true),
		Keys:          keys,
		Store:         store,
		BucketBackend: mpBucket,
		EncFP:         "fp",
		Multipart:     s3api.MultipartConfig{Dir: t.TempDir()},
	})
	require.NoError(t, err)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	const key = "foreign/x.bin"

	owner := newS3Client(srv.URL, "AKIAONE", mpSecretKey)
	other := newS3Client(srv.URL, "AKIATWO", mpSecretKey)

	created, err := owner.CreateMultipartUpload(context.Background(), &s3.CreateMultipartUploadInput{
		Bucket: aws.String(mpBucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err)

	uploadID := aws.ToString(created.UploadId)

	part := func(c *s3.Client, n int32, body []byte) error {
		_, err := c.UploadPart(context.Background(), &s3.UploadPartInput{
			Bucket: aws.String(mpBucket), Key: aws.String(key),
			PartNumber: aws.Int32(n), UploadId: aws.String(uploadID),
			Body: bytes.NewReader(body),
		})

		return err
	}
	// NoSuchUpload, not AccessDenied: the id must not be probeable for existence.
	assert.Equal(t, string(s3err.NoSuchUpload), apiErrCode(t, part(other, 1, patternBytes(64))))

	_, err = other.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(mpBucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{completed(1, `"whatever"`)},
		},
	})
	assert.Equal(t, string(s3err.NoSuchUpload), apiErrCode(t, err))

	_, err = other.AbortMultipartUpload(context.Background(), &s3.AbortMultipartUploadInput{
		Bucket: aws.String(mpBucket), Key: aws.String(key), UploadId: aws.String(uploadID),
	})
	assert.Equal(t, string(s3err.NoSuchUpload), apiErrCode(t, err))

	// The owner is unaffected.
	assert.NoError(t, part(owner, 1, []byte("owner body")))
}

// TestMultipartAbortRemovesFiles pins the cleanup half of the contract: abort
// must take the spooled bytes with it, or AbortMultipartUpload would be a way
// to fill the gateway's disk.
func TestMultipartAbortRemovesFiles(t *testing.T) {
	t.Parallel()

	f := newMPFacade(t, time.Hour)

	const key = "abort/x.bin"

	uploadID := f.createUpload(t, key)
	f.uploadPart(t, key, uploadID, 1, patternBytes(partSize))
	f.uploadPart(t, key, uploadID, 2, patternBytes(1024))
	require.NotEmpty(t, f.sessionDirs(), "parts are on disk while the upload is live")

	_, err := f.client.AbortMultipartUpload(context.Background(), &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(mpBucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	})
	require.NoError(t, err)

	assert.Empty(t, f.sessionDirs(), "abort must remove the session directory")
	assert.Equal(t, 0, f.api.SweepExpired(), "an aborted session is already out of the registry")
}

// TestMultipartCompleteRemovesFiles is the successful counterpart: a completed
// upload must not leave its parts, or the assembled copy, behind either.
func TestMultipartCompleteRemovesFiles(t *testing.T) {
	t.Parallel()

	f := newMPFacade(t, time.Hour)

	const key = "cleanup/x.bin"

	uploadID := f.createUpload(t, key)
	e1 := f.uploadPart(t, key, uploadID, 1, patternBytes(partSize))
	e2 := f.uploadPart(t, key, uploadID, 2, patternBytes(16))
	_, err := f.complete(t, key, uploadID, []types.CompletedPart{completed(1, e1), completed(2, e2)})
	require.NoError(t, err)

	assert.Empty(t, f.sessionDirs(), "a completed upload must clean up its spool directory")
}

// TestMultipartSweeperReclaimsIdleSessions pins step 5 of the plan. Without the
// sweeper an interrupted upload keeps its bytes on disk forever: no other timer
// in s3vault owns the spool directory.
//
// The TTL is short rather than a test hook, because the property under test *is*
// the comparison against touchedAt: one session has to age past the TTL while
// the other does not, and stubbing the clock would assert on the stub instead.
func TestMultipartSweeperReclaimsIdleSessions(t *testing.T) {
	t.Parallel()

	const ttl = 50 * time.Millisecond

	f := newMPFacade(t, ttl)

	const staleKey, freshKey = "sweep/old.bin", "sweep/new.bin"

	stale := f.createUpload(t, staleKey)
	f.uploadPart(t, staleKey, stale, 1, patternBytes(1024))
	// Age the first session past the TTL *before* the second one exists, so
	// their activity clocks are unambiguously different when the sweep runs.
	time.Sleep(3 * ttl)

	fresh := f.createUpload(t, freshKey)
	f.uploadPart(t, freshKey, fresh, 1, patternBytes(1024))

	assert.Equal(t, 1, f.api.SweepExpired(), "only the idle session is swept")
	assert.Len(t, f.sessionDirs(), 1, "the active session keeps its parts")

	// The swept id is gone for good, not merely forgotten.
	_, err := f.client.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket: aws.String(mpBucket), Key: aws.String(staleKey),
		PartNumber: aws.Int32(2), UploadId: aws.String(stale),
		Body: bytes.NewReader([]byte("late")),
	})
	assert.Equal(t, string(s3err.NoSuchUpload), apiErrCode(t, err))

	// The fresh one still works, and a second sweep does not take it: an
	// UploadPart bumps the activity clock, so a long upload in progress is not
	// evicted mid-flight.
	_, err = f.client.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket: aws.String(mpBucket), Key: aws.String(freshKey),
		PartNumber: aws.Int32(2), UploadId: aws.String(fresh),
		Body: bytes.NewReader([]byte("still here")),
	})
	require.NoError(t, err)
	assert.Equal(t, 0, f.api.SweepExpired())
}

// TestMultipartSweeperStopsWithContext pins that the loop runs once at start —
// before its first tick — and that it does not outlive the server's context. A
// leaked sweeper would keep a directory handle and a session registry alive
// after the process has been asked to shut down.
func TestMultipartSweeperStopsWithContext(t *testing.T) {
	t.Parallel()

	const ttl = 30 * time.Millisecond

	f := newMPFacade(t, ttl)

	const key = "loop/x.bin"
	f.uploadPart(t, key, f.createUpload(t, key), 1, patternBytes(256))
	time.Sleep(3 * ttl) // now eligible

	ctx, cancel := context.WithCancel(context.Background())
	f.api.StartSweeper(ctx, time.Hour) // a one-hour interval: only the first run can act
	require.Eventually(t, func() bool { return len(f.sessionDirs()) == 0 }, 2*time.Second, 5*time.Millisecond,
		"the first sweep runs at start, without waiting for the first tick")
	cancel()

	// With the loop stopped, a later-eligible session is still there when the
	// test sweeps by hand.
	const later = "loop/later.bin"
	f.uploadPart(t, later, f.createUpload(t, later), 1, patternBytes(256))
	time.Sleep(300 * time.Millisecond) // 10 sweep intervals, had the loop survived
	assert.Equal(t, 1, f.api.SweepExpired(), "the background loop must have stopped with its context")
}

// TestMultipartPerSessionByteLimit pins the other disk guard: a part that would
// push its session over the budget is rejected and removed, not left for the
// sweeper.
func TestMultipartPerSessionByteLimit(t *testing.T) {
	t.Parallel()

	f := newMPFacade(t, time.Hour, func(m *s3api.MultipartConfig) { m.MaxBytes = partSize + 1024 })

	const key = "budget/x.bin"

	uploadID := f.createUpload(t, key)

	_, err := f.client.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket: aws.String(mpBucket), Key: aws.String(key),
		PartNumber: aws.Int32(1), UploadId: aws.String(uploadID),
		Body: bytes.NewReader(patternBytes(partSize)),
	})
	require.NoError(t, err, "the first part fits inside the budget")

	_, err = f.client.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket: aws.String(mpBucket), Key: aws.String(key),
		PartNumber: aws.Int32(2), UploadId: aws.String(uploadID),
		Body: bytes.NewReader(patternBytes(partSize)),
	})
	require.Error(t, err, "the second part would take the session over its budget")

	entries, err := f.sessionPartFiles()
	require.NoError(t, err)
	assert.Len(t, entries, 1, "the rejected part was removed, not left for the sweeper")
}

// TestMultipartReUploadReplacesPart pins S3 semantics the SDK relies on when it
// retries a part: the same number overwrites, and the ETag follows the bytes.
func TestMultipartReUploadReplacesPart(t *testing.T) {
	t.Parallel()

	f := newMPFacade(t, time.Hour)

	const key = "replace/x.bin"

	uploadID := f.createUpload(t, key)

	first := f.uploadPart(t, key, uploadID, 1, patternBytes(partSize))
	retry := f.uploadPart(t, key, uploadID, 1, patternBytes(64))
	assert.NotEqual(t, first, retry, "the ETag must follow the new bytes")

	list, err := f.client.ListParts(context.Background(), &s3.ListPartsInput{
		Bucket: aws.String(mpBucket), Key: aws.String(key), UploadId: aws.String(uploadID),
	})
	require.NoError(t, err)
	require.Len(t, list.Parts, 1)
	assert.Equal(t, retry, aws.ToString(list.Parts[0].ETag))
	assert.Equal(t, int64(64), aws.ToInt64(list.Parts[0].Size))
}

// TestMultipartPostWithoutParamsIsNotMethodNotAllowed pins the routing decision:
// a bare POST is a browser form upload, which this facade does not serve, so it
// is NotImplemented. MethodNotAllowed claims the verb is unknown, which is what
// a client reads as a broken endpoint.
func TestMultipartPostWithoutParamsIsNotMethodNotAllowed(t *testing.T) {
	t.Parallel()

	f := newMPFacade(t, time.Hour)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/vault/a.txt", strings.NewReader("x"))
	rr := httptest.NewRecorder()
	f.api.Handler().ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotImplemented, rr.Code)
	assert.Contains(t, rr.Body.String(), string(s3err.NotImplemented))
	assert.NotContains(t, rr.Body.String(), string(s3err.MethodNotAllowed))
}

// TestUnknownMethodStillMethodNotAllowed keeps the old 405 for verbs that are
// genuinely not part of the S3 API: giving POST its own case must not have turned
// every unknown method into NotImplemented.
func TestUnknownMethodStillMethodNotAllowed(t *testing.T) {
	t.Parallel()

	f := newMPFacade(t, time.Hour)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/vault/a.txt", nil)
	rr := httptest.NewRecorder()
	f.api.Handler().ServeHTTP(rr, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	assert.Contains(t, rr.Body.String(), string(s3err.MethodNotAllowed))
}

// TestMultipartListPartsAscending pins the inventory shape, including that the
// ETags are the ones the client must echo back in its completion list.
func TestMultipartListPartsAscending(t *testing.T) {
	t.Parallel()

	f := newMPFacade(t, time.Hour)

	const key = "inventory/x.bin"

	uploadID := f.createUpload(t, key)
	// Uploaded 3, 2, 1. Every part but the last must reach the S3 5 MiB minimum,
	// so the lengths differ only in the last one.
	sizes := map[int32]int64{3: partSize, 2: partSize, 1: partSize + 16}

	var etags [4]string
	for _, n := range []int32{3, 2, 1} {
		etags[n] = f.uploadPart(t, key, uploadID, n, patternBytes(sizes[n]))
	}

	list, err := f.client.ListParts(context.Background(), &s3.ListPartsInput{
		Bucket: aws.String(mpBucket), Key: aws.String(key), UploadId: aws.String(uploadID),
	})
	require.NoError(t, err)
	require.Len(t, list.Parts, 3)

	for i, p := range list.Parts {
		n := int32(i + 1)
		assert.Equal(t, n, aws.ToInt32(p.PartNumber), "parts are listed in ascending order")
		assert.Equal(t, etags[n], aws.ToString(p.ETag))
		assert.Equal(t, sizes[n], aws.ToInt64(p.Size))
	}

	// And the list is good enough to complete from.
	_, err = f.complete(t, key, uploadID, []types.CompletedPart{
		completed(1, etags[1]), completed(2, etags[2]), completed(3, etags[3]),
	})
	require.NoError(t, err)
}

// TestMultipartCacheInvalidatedOnComplete pins that a read right after a
// multipart write cannot be served the previous version from the plaintext cache
// — the same rule handlePut follows, applied to the second write path.
func TestMultipartCacheInvalidatedOnComplete(t *testing.T) {
	t.Parallel()

	store := newMemStore()
	disk, err := cache.New(cache.Options{Dir: t.TempDir(), TTL: time.Hour, MaxBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { _ = disk.Close() })

	keys := keying.Mapper{Prefix: mpKeyPrefix}
	api, err := s3api.New(s3api.Config{
		Identity: &s3auth.Static{AccessKey: mpAccessKey, SecretKey: mpSecretKey, Bucket: mpBucket},
		Region:   mpRegion,
		Bucket:   mpBucket,
		Fetch: service.NewFetch(store, encrypt.Passthrough{}).
			WithCache(disk, mpBucket, "fp").
			// A long window: only write-through invalidation can save this read.
			WithSoftTTL(time.Hour),
		Archive:       service.NewArchive(scanner.New(scanner.Options{}), keys, store, encrypt.Passthrough{}, nil).WithFraming(true),
		Keys:          keys,
		Store:         store,
		Cache:         disk,
		BucketBackend: mpBucket,
		EncFP:         "fp",
		Multipart:     s3api.MultipartConfig{Dir: t.TempDir()},
	})
	require.NoError(t, err)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	client := newS3Client(srv.URL, mpAccessKey, mpSecretKey)

	const key = "cache/x.bin"

	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(mpBucket), Key: aws.String(key), Body: bytes.NewReader([]byte("version-one")),
	})
	require.NoError(t, err)
	assert.Equal(t, "version-one", string(readObject(t, client, key)), "warm the plaintext cache")

	uploadID := createMultipart(t, client, key)
	part, err := client.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket: aws.String(mpBucket), Key: aws.String(key),
		PartNumber: aws.Int32(1), UploadId: aws.String(uploadID),
		Body: bytes.NewReader([]byte("version-two")),
	})
	require.NoError(t, err)
	_, err = client.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(mpBucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{completed(1, aws.ToString(part.ETag))},
		},
	})
	require.NoError(t, err)

	assert.Equal(t, "version-two", string(readObject(t, client, key)),
		"a read after a successful Complete must not serve the cached version")
}

// --- helpers ---------------------------------------------------------------

// sessionDirs lists the session directories in the spool root.
func (f *mpFacade) sessionDirs() []string {
	entries, err := os.ReadDir(f.spool)
	if err != nil {
		return nil
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}

	return names
}

// sessionPartFiles lists every part file across every session.
func (f *mpFacade) sessionPartFiles() ([]string, error) {
	var out []string

	for _, dir := range f.sessionDirs() {
		entries, err := os.ReadDir(filepath.Join(f.spool, dir))
		if err != nil {
			return nil, err
		}

		for _, e := range entries {
			out = append(out, e.Name())
		}
	}

	return out, nil
}

func createMultipart(t *testing.T, c *s3.Client, key string) string {
	t.Helper()

	out, err := c.CreateMultipartUpload(context.Background(), &s3.CreateMultipartUploadInput{
		Bucket: aws.String(mpBucket), Key: aws.String(key),
	})
	require.NoError(t, err)

	return aws.ToString(out.UploadId)
}

func readObject(t *testing.T, c *s3.Client, key string) []byte {
	t.Helper()

	got, err := c.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(mpBucket), Key: aws.String(key),
	})
	require.NoError(t, err)

	defer func() { _ = got.Body.Close() }()

	body, err := io.ReadAll(got.Body)
	require.NoError(t, err)

	return body
}

func mustHead(t *testing.T, f *mpFacade, key string) *s3.HeadObjectOutput {
	t.Helper()

	out, err := f.client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String(mpBucket), Key: aws.String(key),
	})
	require.NoError(t, err)

	return out
}

// patternBytes returns n deterministic, non-repeating bytes. Random content
// would make a mis-ordered assembly hard to read in a failure message.
func patternBytes(n int64) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + i/251)
	}

	return b
}

// twoPrincipalIdentity resolves two access keys to the same bucket, so a test can
// act as a second principal without changing the facade's structure.
type twoPrincipalIdentity struct{ bucket string }

var _ port.S3Identity = (*twoPrincipalIdentity)(nil)

func (i *twoPrincipalIdentity) Lookup(_ context.Context, accessKeyID string) (port.Principal, bool, error) {
	switch accessKeyID {
	case "AKIAONE", "AKIATWO":
		return port.Principal{
			AccessKeyID:    accessKeyID,
			SecretKey:      mpSecretKey,
			AllowedBuckets: []string{i.bucket},
		}, true, nil
	default:
		return port.Principal{}, false, nil
	}
}

func (i *twoPrincipalIdentity) Allow(_ context.Context, _ port.Principal, _ port.S3Op, bucket, _ string) error {
	if !strings.EqualFold(bucket, i.bucket) {
		return port.ErrAccessDenied
	}

	return nil
}
