//go:build integration

package s3api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	postgresauth "github.com/xMlex/s3vault/internal/adapter/s3auth/postgres"
	"github.com/xMlex/s3vault/internal/adapter/s3auth/secretbox"
	"github.com/xMlex/s3vault/internal/adapter/s3target"
	"github.com/xMlex/s3vault/internal/adapter/scanner"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api"
	"github.com/xMlex/s3vault/internal/service"
)

const postgresTestMasterKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func TestFacadePostgresUsers(t *testing.T) {
	dsn := os.Getenv("S3VAULT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("S3VAULT_TEST_POSTGRES_DSN is not set")
	}

	ctx := t.Context()
	key, err := secretbox.ParseKey(postgresTestMasterKey)
	require.NoError(t, err)

	resolver, err := encrypt.NewResolver(config.EncryptionConfig{Mode: "none"})
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	// The table may not exist yet; Open's migration creates it.
	_, _ = pool.Exec(ctx, "TRUNCATE s3vault_users, s3vault_targets, s3vault_encryption_profiles RESTART IDENTITY")

	id, err := postgresauth.Open(ctx, postgresauth.Config{
		DSN:          dsn,
		MaxConns:     2,
		QueryTimeout: 2 * time.Second,
		MasterKey:    key,
		Bucket:       "s3vault",
		ValidateEncryption: func(raw json.RawMessage) error {
			_, err := resolver.ResolveRaw(raw)
			return err
		},
	})
	require.NoError(t, err)
	t.Cleanup(id.Close)

	_, err = pool.Exec(ctx, "TRUNCATE s3vault_users, s3vault_targets, s3vault_encryption_profiles RESTART IDENTITY")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "TRUNCATE s3vault_users, s3vault_targets, s3vault_encryption_profiles RESTART IDENTITY")
	})

	alice, aliceSecret, err := id.AddUser(ctx, postgresauth.AddParams{Name: "alice", Prefix: "tenant-a"})
	require.NoError(t, err)
	bob, bobSecret, err := id.AddUser(ctx, postgresauth.AddParams{Name: "bob", Prefix: "tenant-b"})
	require.NoError(t, err)

	kekPath := filepath.Join(t.TempDir(), "kek.bin")
	require.NoError(t, os.WriteFile(kekPath, []byte("0123456789abcdef0123456789abcdef"), 0o600))
	nativeConfig := json.RawMessage(fmt.Sprintf(
		`{"mode":"native","native":{"wrap":"keyfile","key_file":%q}}`, kekPath,
	))
	nativeProfile, err := id.AddEncryptionProfile(ctx, "shared-native", nativeConfig)
	require.NoError(t, err)

	carol, carolSecret, err := id.AddUser(ctx, postgresauth.AddParams{
		Name: "carol", Prefix: "tenant-c", EncryptionProfileName: nativeProfile.Name,
	})
	require.NoError(t, err)
	// The same shared profile may be assigned to more than one user.
	dave, daveSecret, err := id.AddUser(ctx, postgresauth.AddParams{
		Name: "dave", Prefix: "tenant-d", EncryptionProfileName: nativeProfile.Name,
	})
	require.NoError(t, err)

	store := newMemStore()
	globalEnc := encrypt.Passthrough{}
	keys := keying.Mapper{}
	archive := service.NewArchive(scanner.New(scanner.Options{}), keys, store, globalEnc, nil).WithFraming(true)
	fetch := service.NewFetch(store, globalEnc).WithSpoolDir(t.TempDir())
	targets := newMemTargets()

	api, err := s3api.New(s3api.Config{
		Identity:      id,
		Region:        "us-east-1",
		Bucket:        "s3vault",
		Fetch:         fetch,
		Archive:       archive,
		Profiles:      resolver,
		Keys:          keys,
		Store:         store,
		Targets:       targets,
		BucketBackend: "s3vault",
		EncFP:         resolver.Default().Fingerprint,
		Multipart:     s3api.MultipartConfig{Dir: t.TempDir()},
		SpoolDir:      t.TempDir(),
		SpoolTTL:      time.Hour,
		PutMaxBytes:   5 << 20,
	})
	require.NoError(t, err)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	aliceClient := newS3Client(srv.URL, alice.AccessKeyID, aliceSecret)
	bobClient := newS3Client(srv.URL, bob.AccessKeyID, bobSecret)
	carolClient := newS3Client(srv.URL, carol.AccessKeyID, carolSecret)
	daveClient := newS3Client(srv.URL, dave.AccessKeyID, daveSecret)

	_, err = aliceClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/file.txt"), Body: bytes.NewReader([]byte("alice")),
	})
	require.NoError(t, err)
	_, err = bobClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/file.txt"), Body: bytes.NewReader([]byte("bob")),
	})
	require.NoError(t, err)

	assert.True(t, bytes.HasSuffix(store.body["tenant-a/dir/file.txt"], []byte("alice")))
	assert.True(t, bytes.HasSuffix(store.body["tenant-b/dir/file.txt"], []byte("bob")))

	_, err = carolClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/native.txt"), Body: bytes.NewReader([]byte("carol native")),
	})
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(store.body["tenant-c/dir/native.txt"], []byte("S3VCTR01")),
		"a per-user native profile must frame the gateway layer")

	gotNative, err := carolClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/native.txt"),
	})
	require.NoError(t, err)
	nativeBody, err := io.ReadAll(gotNative.Body)
	require.NoError(t, err)
	require.NoError(t, gotNative.Body.Close())
	assert.Equal(t, []byte("carol native"), nativeBody)

	// The same native profile works for a second user: both frame their layer
	// and read it back, under their own prefixes.
	_, err = daveClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/native.txt"), Body: bytes.NewReader([]byte("dave native")),
	})
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(store.body["tenant-d/dir/native.txt"], []byte("S3VCTR01")))

	gotDave, err := daveClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/native.txt"),
	})
	require.NoError(t, err)
	daveBody, err := io.ReadAll(gotDave.Body)
	require.NoError(t, err)
	require.NoError(t, gotDave.Body.Close())
	assert.Equal(t, []byte("dave native"), daveBody)

	got, err := aliceClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/file.txt"),
	})
	require.NoError(t, err)
	body, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	require.NoError(t, got.Body.Close())
	assert.Equal(t, []byte("alice"), body)

	list, err := aliceClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("s3vault")})
	require.NoError(t, err)
	require.Len(t, list.Contents, 1)
	assert.Equal(t, "dir/file.txt", aws.ToString(list.Contents[0].Key))

	_, err = aliceClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("../tenant-b/dir/file.txt"),
	})
	require.Error(t, err)

	_, err = aliceClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/file.txt"),
	})
	require.NoError(t, err)
	assert.NotContains(t, store.body, "tenant-a/dir/file.txt")
	assert.Contains(t, store.body, "tenant-b/dir/file.txt")

	require.NoError(t, id.SetEnabled(ctx, alice.AccessKeyID, false))
	_, err = aliceClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/file.txt"),
	})
	require.Error(t, err)
}

func TestFacadePostgresTarget(t *testing.T) {
	dsn := os.Getenv("S3VAULT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("S3VAULT_TEST_POSTGRES_DSN is not set")
	}

	ctx := t.Context()
	key, err := secretbox.ParseKey(postgresTestMasterKey)
	require.NoError(t, err)

	resolver, err := encrypt.NewResolver(config.EncryptionConfig{Mode: "none"})
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	_, _ = pool.Exec(ctx, "TRUNCATE s3vault_users, s3vault_targets, s3vault_encryption_profiles RESTART IDENTITY")

	id, err := postgresauth.Open(ctx, postgresauth.Config{
		DSN:          dsn,
		MaxConns:     2,
		QueryTimeout: 2 * time.Second,
		MasterKey:    key,
		Bucket:       "s3vault",
		ValidateEncryption: func(raw json.RawMessage) error {
			_, err := resolver.ResolveRaw(raw)
			return err
		},
	})
	require.NoError(t, err)
	t.Cleanup(id.Close)

	_, err = pool.Exec(ctx, "TRUNCATE s3vault_users, s3vault_targets, s3vault_encryption_profiles RESTART IDENTITY")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "TRUNCATE s3vault_users, s3vault_targets, s3vault_encryption_profiles RESTART IDENTITY")
	})

	target := &port.S3Target{
		Endpoint:     "https://target.example.com",
		Region:       "us-east-1",
		Bucket:       "alt",
		Prefix:       "vault",
		AccessKey:    "AKIATARGET",
		SecretKey:    "secret",
		SSEKMS:       &port.SSEKMS{KeyID: "alias/vault", Context: map[string]string{"tenant": "dave"}, BucketKey: true},
		StorageClass: "STANDARD_IA",
	}

	targetInfo, err := id.AddTarget(ctx, "alt", *target)
	require.NoError(t, err)

	dave, daveSecret, err := id.AddUser(ctx, postgresauth.AddParams{
		Name: "dave", Prefix: "tenant-d", TargetName: targetInfo.Name,
	})
	require.NoError(t, err)
	// A second user may reference the same shared destination; the pool hands
	// both the same store.
	frank, frankSecret, err := id.AddUser(ctx, postgresauth.AddParams{
		Name: "frank", Prefix: "tenant-f", TargetName: targetInfo.Name,
	})
	require.NoError(t, err)
	erin, erinSecret, err := id.AddUser(ctx, postgresauth.AddParams{Name: "erin", Prefix: "tenant-e"})
	require.NoError(t, err)

	global := newMemStore()
	globalEnc := encrypt.Passthrough{}
	keys := keying.Mapper{}
	archive := service.NewArchive(scanner.New(scanner.Options{}), keys, global, globalEnc, nil).WithFraming(true)
	fetch := service.NewFetch(global, globalEnc).WithSpoolDir(t.TempDir())
	targets := newMemTargets()

	api, err := s3api.New(s3api.Config{
		Identity:      id,
		Region:        "us-east-1",
		Bucket:        "s3vault",
		Fetch:         fetch,
		Archive:       archive,
		Profiles:      resolver,
		Keys:          keys,
		Store:         global,
		Targets:       targets,
		BucketBackend: "s3vault",
		EncFP:         resolver.Default().Fingerprint,
		Multipart:     s3api.MultipartConfig{Dir: t.TempDir()},
		SpoolDir:      t.TempDir(),
		SpoolTTL:      time.Hour,
		PutMaxBytes:   5 << 20,
	})
	require.NoError(t, err)

	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	daveClient := newS3Client(srv.URL, dave.AccessKeyID, daveSecret)
	frankClient := newS3Client(srv.URL, frank.AccessKeyID, frankSecret)
	erinClient := newS3Client(srv.URL, erin.AccessKeyID, erinSecret)

	_, err = daveClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/dave.txt"), Body: bytes.NewReader([]byte("dave")),
	})
	require.NoError(t, err)
	_, err = daveClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/old.txt"), Body: bytes.NewReader([]byte("old")),
	})
	require.NoError(t, err)
	_, err = frankClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/frank.txt"), Body: bytes.NewReader([]byte("frank")),
	})
	require.NoError(t, err)
	_, err = erinClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/erin.txt"), Body: bytes.NewReader([]byte("erin")),
	})
	require.NoError(t, err)

	alt := targets.forTarget(*target)
	require.NotNil(t, alt)
	assert.Contains(t, alt.body, "vault/tenant-d/dir/dave.txt")
	assert.Contains(t, alt.body, "vault/tenant-f/dir/frank.txt",
		"a second user with the same target shares its store but keeps its own prefix")
	assert.NotContains(t, global.body, "vault/tenant-d/dir/dave.txt")
	assert.Contains(t, global.body, "tenant-e/dir/erin.txt")

	// List and Delete stay inside the target store.
	list, err := daveClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("s3vault")})
	require.NoError(t, err)
	require.Len(t, list.Contents, 2)

	_, err = daveClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/dave.txt"),
	})
	require.NoError(t, err)
	assert.NotContains(t, alt.body, "vault/tenant-d/dir/dave.txt")

	// A new target replaces the old one: the old key is no longer addressable,
	// and new writes land in the new store.
	next := *target
	next.Bucket = "alt-two"
	_, err = id.UpdateTarget(ctx, "alt", next, "alt-two")
	require.NoError(t, err)

	_, err = daveClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/old.txt"),
	})
	require.Error(t, err, "an object in the replaced target is not visible through the gateway")

	_, err = daveClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/next.txt"), Body: bytes.NewReader([]byte("next")),
	})
	require.NoError(t, err)

	nextStore := targets.forTarget(next)
	require.NotNil(t, nextStore)
	assert.Contains(t, nextStore.body, "vault/tenant-d/dir/next.txt")

	// Multipart is bound to the target fingerprint: changing the target between
	// UploadPart and Complete rejects the upload, while Abort still works.
	created, err := daveClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String("s3vault"), Key: aws.String("dir/mp.bin"),
	})
	require.NoError(t, err)

	part, err := daveClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:     aws.String("s3vault"),
		Key:        aws.String("dir/mp.bin"),
		UploadId:   created.UploadId,
		PartNumber: aws.Int32(1),
		Body:       bytes.NewReader([]byte("multipart body")),
	})
	require.NoError(t, err)

	third := next
	third.Bucket = "alt-three"
	_, err = id.UpdateTarget(ctx, "alt-two", third, "alt-three")
	require.NoError(t, err)

	_, err = daveClient.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String("s3vault"),
		Key:      aws.String("dir/mp.bin"),
		UploadId: created.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{{ETag: part.ETag, PartNumber: aws.Int32(1)}},
		},
	})
	require.Error(t, err)
	assert.Equal(t, "NoSuchUpload", apiErrorCode(t, err))

	_, err = daveClient.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String("s3vault"),
		Key:      aws.String("dir/mp.bin"),
		UploadId: created.UploadId,
	})
	require.NoError(t, err)
}

// memTargets is a TargetResolver stub: every distinct target fingerprint gets
// its own in-memory store.
type memTargets struct {
	mu     sync.Mutex
	stores map[string]*memStore
}

func newMemTargets() *memTargets {
	return &memTargets{stores: map[string]*memStore{}}
}

func (m *memTargets) Store(_ context.Context, t port.S3Target) (port.ObjectStore, error) {
	key := s3target.Fingerprint(t)

	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.stores[key]; ok {
		return s, nil
	}

	s := newMemStore()
	m.stores[key] = s

	return s, nil
}

func (m *memTargets) forTarget(t port.S3Target) *memStore {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.stores[s3target.Fingerprint(t)]
}

func apiErrorCode(t *testing.T, err error) string {
	t.Helper()

	var apiErr smithy.APIError
	require.ErrorAs(t, err, &apiErr)

	return apiErr.ErrorCode()
}
