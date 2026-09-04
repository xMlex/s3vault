package identity_test

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
)

type rangeStore struct {
	mu   sync.Mutex
	meta map[string]domain.ObjectMeta
	body map[string][]byte
}

func (s *rangeStore) Head(_ context.Context, key string) (domain.ObjectMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.meta[key]
	if !ok {
		return domain.ObjectMeta{Key: key, Exists: false}, nil
	}
	return m, nil
}

func (s *rangeStore) Put(context.Context, string, io.Reader, domain.PutMeta) error {
	return nil
}

func (s *rangeStore) Get(_ context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.body[key]
	if !ok {
		return nil, domain.ObjectMeta{}, domain.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(b)), s.meta[key], nil
}

func (s *rangeStore) GetRange(_ context.Context, key string, start, end int64) (io.ReadCloser, domain.ObjectMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.body[key]
	if !ok {
		return nil, domain.ObjectMeta{}, domain.ErrNotFound
	}
	to := end + 1
	if to > int64(len(b)) {
		to = int64(len(b))
	}
	if start >= int64(len(b)) {
		return io.NopCloser(bytes.NewReader(nil)), s.meta[key], nil
	}
	return io.NopCloser(bytes.NewReader(b[start:to])), s.meta[key], nil
}

func TestResolveRemotePrefersContainerOverHEAD(t *testing.T) {
	t.Parallel()
	sum, err := container.SHA256FromHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	require.NoError(t, err)
	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: 7,
		SHA256:        sum,
		Enc:           container.EncNative,
		Wrap:          container.WrapRSA,
	})
	require.NoError(t, err)
	body := append(hdr, []byte("payload")...)
	store := &rangeStore{
		meta: map[string]domain.ObjectMeta{
			"k": {Key: "k", Exists: true, SHA256: "deadbeef", ContentSize: 1, Encrypted: "none"},
		},
		body: map[string][]byte{"k": body},
	}
	got, err := identity.ResolveRemote(context.Background(), store, "k")
	require.NoError(t, err)
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", got.SHA256)
	assert.Equal(t, int64(7), got.ContentSize)
	assert.Equal(t, "native", got.Encrypted)
	assert.Equal(t, "rsa-oaep", got.Wrap)
	assert.Equal(t, container.FormatVersion, got.FormatVersion)
}

func TestResolveRemoteLegacyHEADMeta(t *testing.T) {
	t.Parallel()
	store := &rangeStore{
		meta: map[string]domain.ObjectMeta{
			"k": {Key: "k", Exists: true, SHA256: "aa", ContentSize: 1, Encrypted: "none"},
		},
		body: map[string][]byte{"k": []byte("not-a-container-object-body")},
	}
	got, err := identity.ResolveRemote(context.Background(), store, "k")
	require.NoError(t, err)
	assert.Equal(t, "aa", got.SHA256)
	assert.Equal(t, "none", got.Encrypted)
}

func TestResolveRemoteFallsBackWhenPeekCorruptButHeadHasIdentity(t *testing.T) {
	t.Parallel()
	// Magic matches but CRC is wrong — e.g. raw plaintext that starts like
	// S3VCTR01. Head identity (sidecar / legacy metadata) must still win.
	bad := make([]byte, container.HeaderSize)
	copy(bad, container.Magic)
	store := &rangeStore{
		meta: map[string]domain.ObjectMeta{
			"k": {Key: "k", Exists: true, SHA256: "from-sidecar", ContentSize: 3, Encrypted: "none"},
		},
		body: map[string][]byte{"k": bad},
	}
	got, err := identity.ResolveRemote(context.Background(), store, "k")
	require.NoError(t, err)
	assert.Equal(t, "from-sidecar", got.SHA256)
	assert.Equal(t, int64(3), got.ContentSize)
}

func TestResolveRemoteMissingObject(t *testing.T) {
	t.Parallel()
	store := &rangeStore{meta: map[string]domain.ObjectMeta{}, body: map[string][]byte{}}
	got, err := identity.ResolveRemote(context.Background(), store, "missing")
	require.NoError(t, err)
	assert.False(t, got.Exists)
}
