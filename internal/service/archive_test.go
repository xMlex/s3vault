package service_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/adapter/scanner"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/service"
)

type memStore struct {
	mu             sync.Mutex
	meta           map[string]domain.ObjectMeta
	body           map[string][]byte
	omitMetaOnHead bool // simulate S3 that strips user-metadata
	plaintext      bool // StoresPlaintext: bare payload, no container header
	rangeCalls     int
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
	if m.omitMetaOnHead {
		return domain.ObjectMeta{
			Key:          key,
			Exists:       true,
			Size:         meta.Size,
			ETag:         meta.ETag,
			LastModified: meta.LastModified,
		}, nil
	}
	return meta, nil
}

func (m *memStore) Put(_ context.Context, key string, r io.Reader, _ domain.PutMeta) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	om := domain.ObjectMeta{
		Key:    key,
		Exists: true,
		Size:   int64(len(b)),
	}
	if len(b) >= container.HeaderSize && container.IsMagic(b) {
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
	m.rangeCalls++
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

func (m *memStore) StoresPlaintext() bool { return m.plaintext }

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

// putContained stores S3VCTR01 || plaintext (enc=none) for tests that skip Archive.
func putContained(t *testing.T, store *memStore, key string, plain []byte) {
	t.Helper()
	sum := sha256.Sum256(plain)
	hdr, err := container.Marshal(container.Header{
		Version:       container.VersionV1,
		PlaintextSize: int64(len(plain)),
		SHA256:        sum[:],
		Enc:           container.EncNone,
	})
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), key, io.MultiReader(bytes.NewReader(hdr), bytes.NewReader(plain)), domain.PutMeta{}))
}

func TestArchiveUploadAndSkip(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	p := filepath.Join(root, "a.log")
	require.NoError(t, os.WriteFile(p, []byte("payload"), 0o600))
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(p, old, old))

	store := newMemStore()
	svc := service.NewArchive(
		scanner.New(scanner.Options{}),
		keying.Mapper{Prefix: "pre"},
		store,
		encrypt.Passthrough{},
		nil,
	)
	opts := service.ArchiveOptions{
		Root:      root,
		OlderThan: time.Hour,
		Workers:   2,
	}
	st, err := svc.Run(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, 1, st.Uploaded)
	assert.Equal(t, 1, st.Found)

	body := store.body["pre/a.log"]
	require.True(t, len(body) >= container.HeaderSize)
	assert.True(t, container.IsMagic(body))
	hdr, err := container.Parse(body[:container.HeaderSize])
	require.NoError(t, err)
	assert.Equal(t, container.EncNone, hdr.Enc)
	assert.Equal(t, []byte("payload"), body[container.HeaderSize:])

	st, err = svc.Run(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, 0, st.Uploaded)
	assert.Equal(t, 1, st.Skipped)
}

func TestArchiveSkipViaContainerWithoutMetadata(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	p := filepath.Join(root, "a.log")
	require.NoError(t, os.WriteFile(p, []byte("payload"), 0o600))
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(p, old, old))

	store := newMemStore()
	store.omitMetaOnHead = true
	svc := service.NewArchive(
		scanner.New(scanner.Options{}),
		keying.Mapper{Prefix: "pre"},
		store,
		encrypt.Passthrough{},
		nil,
	)
	opts := service.ArchiveOptions{
		Root: root, OlderThan: time.Hour, Workers: 1,
	}
	st, err := svc.Run(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, 1, st.Uploaded)

	st, err = svc.Run(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, 0, st.Uploaded)
	assert.Equal(t, 1, st.Skipped)
}

func TestArchivePlaintextStoreSkipsHashAndRangePeek(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	p := filepath.Join(root, "a.log")
	require.NoError(t, os.WriteFile(p, []byte("payload"), 0o600))
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(p, old, old))

	store := newMemStore()
	store.plaintext = true
	svc := service.NewArchive(
		scanner.New(scanner.Options{}),
		keying.Mapper{Prefix: "pre"},
		store,
		encrypt.Passthrough{},
		nil,
	)
	opts := service.ArchiveOptions{
		Root: root, OlderThan: time.Hour, Workers: 1,
	}
	st, err := svc.Run(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, 1, st.Uploaded)
	assert.Equal(t, []byte("payload"), store.body["pre/a.log"],
		"plaintext store receives bare payload, no S3VCTR01")
	assert.Zero(t, store.rangeCalls, "plaintext store must not range-peek for a header")

	// A rerun has no remote content hash to compare, so it re-uploads rather
	// than content-skipping (archive.on_change was removed; there is no
	// "skip because we cannot compare" policy any more).
	st, err = svc.Run(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, 1, st.Uploaded)
	assert.Zero(t, st.Skipped)
	assert.Zero(t, store.rangeCalls)
}

func TestArchiveRequiresBackend(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "a.log")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
	info := domain.FileInfo{AbsPath: p, RelPath: "a.log", Size: 1, ModTime: time.Now()}

	svc := service.NewArchive(scanner.New(scanner.Options{}), keying.Mapper{}, nil, nil, nil)
	_, _, err := svc.UploadFile(context.Background(), info, service.ArchiveOptions{})
	require.ErrorIs(t, err, domain.ErrStoreRequired)

	_, err = svc.Run(context.Background(), service.ArchiveOptions{Root: t.TempDir()})
	require.ErrorIs(t, err, domain.ErrStoreRequired)
}

func TestArchiveNilEncryptor(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "a.log")
	plain := []byte("payload")
	require.NoError(t, os.WriteFile(p, plain, 0o600))

	store := newMemStore()
	svc := service.NewArchive(scanner.New(scanner.Options{}), keying.Mapper{}, store, nil, nil)
	info := domain.FileInfo{AbsPath: p, RelPath: "obj.bin", Size: int64(len(plain)), ModTime: time.Now()}
	_, action, err := svc.UploadFile(context.Background(), info, service.ArchiveOptions{
		ExplicitKey: "obj.bin",
	})
	require.NoError(t, err)
	assert.Equal(t, identity.ActionUpload, action)

	body := store.body["obj.bin"]
	require.GreaterOrEqual(t, len(body), container.HeaderSize)
	assert.True(t, container.IsMagic(body), "nil encryptor still writes a container header")
	assert.Equal(t, plain, body[container.HeaderSize:])
}

func TestArchiveUploadRejectsBadSHA(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "sha.bin")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))

	store := newMemStore()
	svc := service.NewArchive(scanner.New(scanner.Options{}), keying.Mapper{}, store, encrypt.Passthrough{}, nil)
	info := domain.FileInfo{AbsPath: p, RelPath: "sha.bin", Size: 1, ModTime: time.Now()}
	_, _, err := svc.UploadFile(context.Background(), info, service.ArchiveOptions{
		ExplicitKey: "sha.bin", PlaintextSHA256: "not-hex",
	})
	require.Error(t, err)
}

type badThumbEncryptor struct{ encrypt.Passthrough }

func (badThumbEncryptor) CryptoProThumbprint() string { return "not-hex" }

func TestArchiveUploadRejectsBadThumbprint(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "thumb.bin")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))

	store := newMemStore()
	svc := service.NewArchive(scanner.New(scanner.Options{}), keying.Mapper{}, store, badThumbEncryptor{}, nil)
	info := domain.FileInfo{AbsPath: p, RelPath: "thumb.bin", Size: 1, ModTime: time.Now()}
	_, _, err := svc.UploadFile(context.Background(), info, service.ArchiveOptions{
		ExplicitKey: "thumb.bin",
	})
	require.Error(t, err)
}

func TestArchiveFetchNativeThroughContainer(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "kek")
	require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{7}, 32), 0o600))
	enc, err := encrypt.NewNative(config.NativeEnc{Wrap: "keyfile", KeyFile: keyPath, ChunkSize: 32})
	require.NoError(t, err)

	root := t.TempDir()
	p := filepath.Join(root, "a.log")
	plain := []byte("native-through-container")
	require.NoError(t, os.WriteFile(p, plain, 0o600))
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(p, old, old))

	store := newMemStore()
	arch := service.NewArchive(scanner.New(scanner.Options{}), keying.Mapper{Prefix: "pre"}, store, enc, nil)
	st, err := arch.Run(context.Background(), service.ArchiveOptions{
		Root: root, OlderThan: time.Hour, Workers: 1,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, st.Uploaded)
	body := store.body["pre/a.log"]
	require.True(t, container.IsMagic(body))
	assert.True(t, bytes.HasPrefix(body[container.HeaderSize:], []byte("S3VLT01\n")))

	dest := filepath.Join(t.TempDir(), "out")
	require.NoError(t, service.NewFetch(store, enc).Download(context.Background(), "pre/a.log", dest, io.Discard))
	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}

func TestArchiveWritesCryptoProThumbprint(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	p := filepath.Join(root, "a.log")
	require.NoError(t, os.WriteFile(p, []byte("payload"), 0o600))
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(p, old, old))

	tp := "afa43c43975fbfc700f051fd62016e1571e7e025"
	script := filepath.Join(t.TempDir(), "cat.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\ncat\n"), 0o700))
	enc, err := encrypt.NewCommand(config.CommandEnc{
		Encrypt:    []string{script},
		Decrypt:    []string{script},
		Thumbprint: tp,
	})
	require.NoError(t, err)

	store := newMemStore()
	svc := service.NewArchive(scanner.New(scanner.Options{}), keying.Mapper{Prefix: "pre"}, store, enc, nil)
	st, err := svc.Run(context.Background(), service.ArchiveOptions{
		Root: root, OlderThan: time.Hour, Workers: 1,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, st.Uploaded)
	body := store.body["pre/a.log"]
	require.True(t, len(body) >= container.HeaderSize)
	hdr, err := container.Parse(body[:container.HeaderSize])
	require.NoError(t, err)
	assert.Equal(t, tp, hdr.ThumbprintHex())
	assert.Equal(t, container.EncCommand, hdr.Enc)
	assert.Equal(t, "cryptopro", hdr.Provider)
}

func TestUploadFileIgnoresMtimeAndHonorsKey(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	nested := filepath.Join(root, "logs")
	require.NoError(t, os.MkdirAll(nested, 0o700))
	p := filepath.Join(nested, "fresh.log")
	require.NoError(t, os.WriteFile(p, []byte("fresh"), 0o600))

	store := newMemStore()
	scan := scanner.New(scanner.Options{})
	info, err := scan.Stat(root, p)
	require.NoError(t, err)

	svc := service.NewArchive(scan, keying.Mapper{Prefix: "pre"}, store, encrypt.Passthrough{}, nil)
	st, _, err := svc.UploadFile(context.Background(), info, service.ArchiveOptions{
		Root: root,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, st.Found)
	assert.Equal(t, 1, st.Uploaded)
	assert.Contains(t, store.meta, "pre/logs/fresh.log")

	st, _, err = svc.UploadFile(context.Background(), info, service.ArchiveOptions{
		Root:        root,
		ExplicitKey: "custom/name.log",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, st.Uploaded)
	assert.Contains(t, store.meta, "pre/custom/name.log")
}

func TestUploadFileUsesPrecomputedSHA256(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	p := filepath.Join(root, "a.log")
	require.NoError(t, os.WriteFile(p, []byte("on-disk-different"), 0o600))

	store := newMemStore()
	scan := scanner.New(scanner.Options{})
	info, err := scan.Stat(root, p)
	require.NoError(t, err)
	store.meta["pre/a.log"] = domain.ObjectMeta{
		Key:         "pre/a.log",
		Exists:      true,
		SHA256:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ContentSize: info.Size,
	}

	svc := service.NewArchive(scan, keying.Mapper{Prefix: "pre"}, store, encrypt.Passthrough{}, nil)
	st, _, err := svc.UploadFile(context.Background(), info, service.ArchiveOptions{
		Root:            root,
		PlaintextSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, st.Skipped)
	assert.Equal(t, 0, st.Uploaded)
	assert.Nil(t, store.body["pre/a.log"]) // Put never called
}

func TestDeleteAfterUploadAndDeleteIfExists(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	p := filepath.Join(root, "a.log")
	require.NoError(t, os.WriteFile(p, []byte("payload"), 0o600))
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(p, old, old))

	store := newMemStore()
	svc := service.NewArchive(scanner.New(scanner.Options{}), keying.Mapper{Prefix: "pre"}, store, encrypt.Passthrough{}, nil)

	st, err := svc.Run(context.Background(), service.ArchiveOptions{
		Root: root, OlderThan: time.Hour, Workers: 1,
		DeleteAfterUpload: true,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, st.Uploaded)
	_, err = os.Stat(p)
	assert.ErrorIs(t, err, os.ErrNotExist)

	require.NoError(t, os.WriteFile(p, []byte("payload"), 0o600))
	require.NoError(t, os.Chtimes(p, old, old))

	st, err = svc.Run(context.Background(), service.ArchiveOptions{
		Root: root, OlderThan: time.Hour, Workers: 1,
		DeleteAfterUpload: true, // upload path not taken
	})
	require.NoError(t, err)
	assert.Equal(t, 1, st.Skipped)
	_, err = os.Stat(p)
	require.NoError(t, err, "delete-after-upload must not remove on skip")

	st, err = svc.Run(context.Background(), service.ArchiveOptions{
		Root: root, OlderThan: time.Hour, Workers: 1,
		DeleteIfExists: true,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, st.Skipped)
	_, err = os.Stat(p)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// TestDeleteIfExistsOnlyRemovesOnIdenticalSkip pins the delete policy to the
// one action it was written for: --delete-if-exists removes the source only
// when the remote already holds identical content (ActionSkip). Differing
// content is overwritten now (no on_change), and the source must stay in place
// because an upload failure would otherwise lose the only copy.
func TestDeleteIfExistsOnlyRemovesOnIdenticalSkip(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	p := filepath.Join(root, "a.log")
	require.NoError(t, os.WriteFile(p, []byte("new-bytes"), 0o600))
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(p, old, old))

	store := newMemStore()
	store.meta["pre/a.log"] = domain.ObjectMeta{
		Key:         "pre/a.log",
		Exists:      true,
		SHA256:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ContentSize: 9,
	}
	svc := service.NewArchive(scanner.New(scanner.Options{}), keying.Mapper{Prefix: "pre"}, store, encrypt.Passthrough{}, nil)
	st, err := svc.Run(context.Background(), service.ArchiveOptions{
		Root: root, OlderThan: time.Hour, Workers: 1,
		DeleteIfExists: true,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, st.Uploaded, "differing content is overwritten")
	_, err = os.Stat(p)
	require.NoError(t, err, "overwrite path must keep the local file: DeleteIfExists only applies to a skip")
}
