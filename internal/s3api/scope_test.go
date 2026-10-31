package s3api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/adapter/s3target"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/port"
)

const testTenantA = "tenant-a"

func testScope(t *testing.T, prin port.Principal) *scope {
	t.Helper()

	resolver, err := encrypt.NewResolver(config.EncryptionConfig{Mode: "none"})
	require.NoError(t, err)

	api := &API{
		keys:          keying.Mapper{Prefix: "root"},
		bucketBackend: "bucket",
		encFP:         resolver.Default().Fingerprint,
		profiles:      resolver,
	}

	return api.newScope(prin)
}

func TestScopeKeys(t *testing.T) {
	t.Parallel()

	user := port.Principal{User: port.UserPolicy{ID: 7, Prefix: testTenantA}}
	sc := testScope(t, user)

	key, err := sc.backendKey("s3vault", "dir/file.txt")
	require.NoError(t, err)
	assert.Equal(t, "root/tenant-a/dir/file.txt", key)

	_, err = sc.backendKey("s3vault", "../escape")
	require.Error(t, err)

	assert.Equal(t, "bucket|user:7", sc.cacheBucket)
}

func TestScopeListPrefix(t *testing.T) {
	t.Parallel()

	user := port.Principal{User: port.UserPolicy{ID: 7, Prefix: testTenantA}}
	sc := testScope(t, user)

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "root", in: "", want: "root/tenant-a/"},
		{name: "dir", in: "dir", want: "root/tenant-a/dir"},
		{name: "dir slash", in: "dir/", want: "root/tenant-a/dir/"},
		{name: "parent", in: "../x", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := sc.listPrefix("s3vault", tt.in)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestScopeStripKey(t *testing.T) {
	t.Parallel()

	user := port.Principal{User: port.UserPolicy{ID: 7, Prefix: testTenantA}}
	sc := testScope(t, user)

	key, ok := sc.stripKey("s3vault", "root/tenant-a/dir/file.txt")
	require.True(t, ok)
	assert.Equal(t, "dir/file.txt", key)

	_, ok = sc.stripKey("s3vault", "root/tenant-b/file.txt")
	assert.False(t, ok)

	_, ok = sc.stripKey("s3vault", "root/tenant-a")
	assert.True(t, ok)
}

func TestScopeToken(t *testing.T) {
	t.Parallel()

	user := port.Principal{User: port.UserPolicy{ID: 7, Prefix: testTenantA}}
	sc := testScope(t, user)

	encoded := sc.encodeToken("root/tenant-a/key")
	assert.NotEqual(t, "root/tenant-a/key", encoded)

	decoded, err := sc.decodeToken(encoded)
	require.NoError(t, err)
	assert.Equal(t, "root/tenant-a/key", decoded)

	_, err = sc.decodeToken("not base64!")
	require.Error(t, err)

	static := testScope(t, port.Principal{})
	assert.Equal(t, "raw", static.encodeToken("raw"))
}

func TestScopeCacheFingerprint(t *testing.T) {
	t.Parallel()

	static := testScope(t, port.Principal{})
	fp, err := static.cacheFingerprint(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, fp)

	user := testScope(t, port.Principal{User: port.UserPolicy{ID: 7, Prefix: testTenantA}})
	userFP, err := user.cacheFingerprint(context.Background())
	require.NoError(t, err)
	assert.Equal(t, fp, userFP, "nil user profile inherits the gateway profile")
}

func TestScopeStartAfter(t *testing.T) {
	t.Parallel()

	user := port.Principal{User: port.UserPolicy{ID: 7, Prefix: testTenantA}}
	sc := testScope(t, user)

	got, err := sc.startAfter("s3vault", "dir/key")
	require.NoError(t, err)
	assert.Equal(t, "root/tenant-a/dir/key", got)

	_, err = sc.startAfter("s3vault", "../escape")
	require.Error(t, err)
}

type noopStore struct{ port.ObjectStore }

type targetStub struct {
	store port.ObjectStore
	calls int
}

func (s *targetStub) Store(context.Context, port.S3Target) (port.ObjectStore, error) {
	s.calls++

	return s.store, nil
}

func TestScopeTarget(t *testing.T) {
	t.Parallel()

	resolver, err := encrypt.NewResolver(config.EncryptionConfig{Mode: "none"})
	require.NoError(t, err)

	global := &noopStore{}
	targetStore := &noopStore{}
	stub := &targetStub{store: targetStore}

	api := &API{
		keys:          keying.Mapper{Prefix: "root"},
		bucketBackend: "bucket",
		encFP:         resolver.Default().Fingerprint,
		profiles:      resolver,
		store:         global,
		targets:       stub,
	}

	tgt := port.S3Target{
		Endpoint:  "https://s3.example.com",
		Region:    "us-east-1",
		Bucket:    "archive",
		Prefix:    "vault",
		AccessKey: "AKIA",
		SecretKey: "secret",
	}
	sc := api.newScope(port.Principal{User: port.UserPolicy{ID: 7, Prefix: testTenantA, Target: &tgt}})

	// target.prefix replaces the global s3.prefix and is combined with the user prefix.
	key, err := sc.backendKey("s3vault", "dir/file.txt")
	require.NoError(t, err)
	assert.Equal(t, "vault/tenant-a/dir/file.txt", key)

	prefix, err := sc.listPrefix("s3vault", "")
	require.NoError(t, err)
	assert.Equal(t, "vault/tenant-a/", prefix)

	stripped, ok := sc.stripKey("s3vault", "vault/tenant-a/dir/file.txt")
	require.True(t, ok)
	assert.Equal(t, "dir/file.txt", stripped)

	ns := s3target.Namespace(tgt)
	assert.Equal(t, "bucket|user:7|s3:"+ns, sc.cacheBucket)
	assert.Equal(t, s3target.Fingerprint(tgt), sc.targetFingerprint())

	store, err := sc.storeFor(context.Background())
	require.NoError(t, err)
	assert.Same(t, targetStore, store)

	_, err = sc.storeFor(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, stub.calls, "a resolved store is reused for the whole request")

	// No target keeps the global prefix and the global store.
	plain := api.newScope(port.Principal{User: port.UserPolicy{ID: 8, Prefix: "tenant-b"}})
	key, err = plain.backendKey("s3vault", "dir/file.txt")
	require.NoError(t, err)
	assert.Equal(t, "root/tenant-b/dir/file.txt", key)
	assert.Equal(t, "bucket|user:8", plain.cacheBucket)
	assert.Empty(t, plain.targetFingerprint())

	store, err = plain.storeFor(context.Background())
	require.NoError(t, err)
	assert.Same(t, global, store)
}
