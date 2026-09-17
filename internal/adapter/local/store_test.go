package localstore_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	localstore "github.com/xMlex/s3vault/internal/adapter/local"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/container"
	"github.com/xMlex/s3vault/internal/domain"
)

func newStore(t *testing.T) (*localstore.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "objects")
	st, err := localstore.New(config.LocalConfig{Dir: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st, dir
}

func put(t *testing.T, st *localstore.Store, key, body string) {
	t.Helper()
	require.NoError(t, st.Put(context.Background(), key, strings.NewReader(body), domain.PutMeta{}))
}

func TestPutGetRoundtrip(t *testing.T) {
	t.Parallel()
	st, dir := newStore(t)
	ctx := context.Background()

	put(t, st, "logs/2026/app.log", "hello world")

	body, meta, err := st.Get(ctx, "logs/2026/app.log")
	require.NoError(t, err)
	defer body.Close()
	got, err := io.ReadAll(body)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(got))
	assert.True(t, meta.Exists)
	assert.Equal(t, int64(11), meta.Size)
	assert.NotEmpty(t, meta.ETag)

	fi, err := os.Stat(filepath.Join(dir, "logs", "2026", "app.log"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	di, err := os.Stat(filepath.Join(dir, "logs", "2026"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())
}

func TestPutOverwriteChangesETag(t *testing.T) {
	t.Parallel()
	st, _ := newStore(t)
	ctx := context.Background()

	put(t, st, "a.txt", "one")
	first, err := st.Head(ctx, "a.txt")
	require.NoError(t, err)

	put(t, st, "a.txt", "two-longer")
	second, err := st.Head(ctx, "a.txt")
	require.NoError(t, err)

	assert.NotEqual(t, first.ETag, second.ETag)
	assert.Equal(t, int64(10), second.Size)
}

func TestPutLeavesNoTempFiles(t *testing.T) {
	t.Parallel()
	st, dir := newStore(t)

	put(t, st, "a.txt", "one")

	entries, err := os.ReadDir(filepath.Join(dir, ".s3vault-tmp"))
	require.NoError(t, err)
	assert.Empty(t, entries)

	page, err := st.List(context.Background(), domain.ListOptions{})
	require.NoError(t, err)
	require.Len(t, page.Contents, 1)
	assert.Equal(t, "a.txt", page.Contents[0].Key)
}

func TestMissingObject(t *testing.T) {
	t.Parallel()
	st, _ := newStore(t)
	ctx := context.Background()

	meta, err := st.Head(ctx, "nope/missing.txt")
	require.NoError(t, err)
	assert.False(t, meta.Exists)
	assert.Equal(t, "nope/missing.txt", meta.Key)

	_, _, err = st.Get(ctx, "nope/missing.txt")
	require.ErrorIs(t, err, domain.ErrNotFound)

	_, _, err = st.GetRange(ctx, "nope/missing.txt", 0, 127)
	require.ErrorIs(t, err, domain.ErrNotFound)
}

// A key whose parent exists as a regular file cannot be stored on a
// filesystem; reads report it as missing, as S3 would for an absent key.
func TestParentIsFile(t *testing.T) {
	t.Parallel()
	st, _ := newStore(t)
	ctx := context.Background()

	put(t, st, "a", "file")

	meta, err := st.Head(ctx, "a/b")
	require.NoError(t, err)
	assert.False(t, meta.Exists)

	_, _, err = st.Get(ctx, "a/b")
	require.ErrorIs(t, err, domain.ErrNotFound)

	require.Error(t, st.Put(ctx, "a/b", strings.NewReader("x"), domain.PutMeta{}))
	require.NoError(t, st.Delete(ctx, "a/b"))
}

func TestGetRange(t *testing.T) {
	t.Parallel()
	st, _ := newStore(t)
	ctx := context.Background()
	put(t, st, "r.bin", "0123456789")
	put(t, st, "empty.bin", "")

	tests := []struct {
		name  string
		key   string
		start int64
		end   int64
		want  string
	}{
		{name: "inclusive", key: "r.bin", start: 0, end: 3, want: "0123"},
		{name: "middle", key: "r.bin", start: 4, end: 5, want: "45"},
		{name: "single byte", key: "r.bin", start: 9, end: 9, want: "9"},
		{name: "end clamped to size", key: "r.bin", start: 8, end: 127, want: "89"},
		{name: "start past end of object", key: "r.bin", start: 20, end: 127, want: ""},
		{name: "empty object", key: "empty.bin", start: 0, end: 127, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body, meta, err := st.GetRange(ctx, tt.key, tt.start, tt.end)
			require.NoError(t, err)
			defer body.Close()
			got, err := io.ReadAll(body)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
			assert.True(t, meta.Exists)
		})
	}

	_, _, err := st.GetRange(ctx, "r.bin", -1, 5)
	require.Error(t, err)
	_, _, err = st.GetRange(ctx, "r.bin", 5, 4)
	require.Error(t, err)
}

func TestDeleteIsIdempotentAndPrunesDirs(t *testing.T) {
	t.Parallel()
	st, dir := newStore(t)
	ctx := context.Background()

	put(t, st, "deep/nested/a.txt", "x")
	put(t, st, "deep/b.txt", "y")

	require.NoError(t, st.Delete(ctx, "deep/nested/a.txt"))
	_, err := os.Stat(filepath.Join(dir, "deep", "nested"))
	assert.True(t, os.IsNotExist(err), "empty directory should be pruned")
	_, err = os.Stat(filepath.Join(dir, "deep", "b.txt"))
	require.NoError(t, err, "sibling object must survive")

	require.NoError(t, st.Delete(ctx, "deep/nested/a.txt"), "delete of a missing key succeeds")

	require.NoError(t, st.Delete(ctx, "deep/b.txt"))
	_, err = os.Stat(filepath.Join(dir, "deep"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(dir)
	require.NoError(t, err, "store root must never be pruned")
}

func TestInvalidKeysRejected(t *testing.T) {
	t.Parallel()
	st, _ := newStore(t)
	ctx := context.Background()

	keys := []string{
		"",
		"/abs.txt",
		"dir/",
		"../escape.txt",
		"a/../../escape.txt",
		"a//b.txt",
		"./a.txt",
		`a\b.txt`,
		"a\x00b.txt",
		".s3vault-tmp/put-1",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			_, err := st.Head(ctx, key)
			require.ErrorIs(t, err, domain.ErrInvalidPath)
			err = st.Put(ctx, key, strings.NewReader("x"), domain.PutMeta{})
			require.ErrorIs(t, err, domain.ErrInvalidPath)
			_, _, err = st.Get(ctx, key)
			require.ErrorIs(t, err, domain.ErrInvalidPath)
			require.ErrorIs(t, st.Delete(ctx, key), domain.ErrInvalidPath)
		})
	}
}

// A symlink escaping the store root must not be readable through a key.
func TestSymlinkOutsideRootNotReadable(t *testing.T) {
	t.Parallel()
	st, dir := newStore(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(outside, []byte("secret"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "link.txt")))

	_, _, err := st.Get(context.Background(), "link.txt")
	require.Error(t, err)
}

func TestListPrefixAndDelimiter(t *testing.T) {
	t.Parallel()
	st, _ := newStore(t)
	ctx := context.Background()
	for _, key := range []string{
		"backups/a.log",
		"backups/2026/01/x.log",
		"backups/2026/02/y.log",
		"backups/2027/z.log",
		"other/w.log",
	} {
		put(t, st, key, key)
	}

	page, err := st.List(ctx, domain.ListOptions{Prefix: "backups/"})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"backups/2026/01/x.log",
		"backups/2026/02/y.log",
		"backups/2027/z.log",
		"backups/a.log",
	}, keysOf(page))
	assert.Empty(t, page.CommonPrefixes)
	assert.False(t, page.IsTruncated)

	page, err = st.List(ctx, domain.ListOptions{Prefix: "backups/", Delimiter: "/"})
	require.NoError(t, err)
	assert.Equal(t, []string{"backups/a.log"}, keysOf(page))
	assert.Equal(t, []string{"backups/2026/", "backups/2027/"}, page.CommonPrefixes)
	assert.Equal(t, int32(3), page.KeyCount)

	page, err = st.List(ctx, domain.ListOptions{Delimiter: "/"})
	require.NoError(t, err)
	assert.Empty(t, keysOf(page))
	assert.Equal(t, []string{"backups/", "other/"}, page.CommonPrefixes)
}

func TestListPagination(t *testing.T) {
	t.Parallel()
	st, _ := newStore(t)
	ctx := context.Background()
	for _, key := range []string{"a.log", "b.log", "c.log", "d.log"} {
		put(t, st, key, key)
	}

	var seen []string
	token := ""
	for range 4 {
		page, err := st.List(ctx, domain.ListOptions{MaxKeys: 2, ContinuationToken: token})
		require.NoError(t, err)
		seen = append(seen, keysOf(page)...)
		if !page.IsTruncated {
			assert.Empty(t, page.NextContinuationToken)
			break
		}
		require.NotEmpty(t, page.NextContinuationToken)
		token = page.NextContinuationToken
	}
	assert.Equal(t, []string{"a.log", "b.log", "c.log", "d.log"}, seen)

	page, err := st.List(ctx, domain.ListOptions{StartAfter: "b.log"})
	require.NoError(t, err)
	assert.Equal(t, []string{"c.log", "d.log"}, keysOf(page))
}

// With a delimiter, a continuation token points past the whole group so the
// next page never repeats a common prefix.
func TestListPaginationWithDelimiter(t *testing.T) {
	t.Parallel()
	st, _ := newStore(t)
	ctx := context.Background()
	for _, key := range []string{"a/1", "a/2", "b/1", "c/1", "d.log"} {
		put(t, st, key, key)
	}

	var prefixes, objects []string
	token := ""
	for range 5 {
		page, err := st.List(ctx, domain.ListOptions{Delimiter: "/", MaxKeys: 1, ContinuationToken: token})
		require.NoError(t, err)
		prefixes = append(prefixes, page.CommonPrefixes...)
		objects = append(objects, keysOf(page)...)
		if !page.IsTruncated {
			break
		}
		token = page.NextContinuationToken
	}
	assert.Equal(t, []string{"a/", "b/", "c/"}, prefixes)
	assert.Equal(t, []string{"d.log"}, objects)
}

func TestNewRequiresDirAndCleansTemp(t *testing.T) {
	t.Parallel()

	_, err := localstore.New(config.LocalConfig{})
	require.Error(t, err)

	dir := filepath.Join(t.TempDir(), "objects")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".s3vault-tmp"), 0o700))
	stale := filepath.Join(dir, ".s3vault-tmp", "put-1-1")
	require.NoError(t, os.WriteFile(stale, []byte("partial"), 0o600))

	st, err := localstore.New(config.LocalConfig{Dir: dir})
	require.NoError(t, err)
	defer st.Close()

	_, err = os.Stat(stale)
	assert.True(t, os.IsNotExist(err), "interrupted Put temp files are dropped at open")
}

func TestStoreCapabilities(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	st, err := localstore.New(config.LocalConfig{Dir: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	assert.Equal(t, config.LocalLayoutContainer, st.Layout())
	assert.False(t, st.StoresPlaintext())
	assert.Equal(t, dir, st.Dir())

	rawDir := t.TempDir()
	raw, err := localstore.New(config.LocalConfig{Dir: rawDir, Layout: config.LocalLayoutRaw})
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	assert.Equal(t, config.LocalLayoutRaw, raw.Layout())
	assert.True(t, raw.StoresPlaintext())
	assert.Equal(t, rawDir, raw.Dir())
}

func TestNewRejectsUnsupportedLayout(t *testing.T) {
	t.Parallel()
	_, err := localstore.New(config.LocalConfig{Dir: t.TempDir(), Layout: "bogus"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

// A key that names a directory is not an object: reads report it as missing.
func TestHeadOnDirectoryKey(t *testing.T) {
	t.Parallel()
	st, _ := newStore(t)
	ctx := context.Background()
	put(t, st, "dir/obj", "x")

	meta, err := st.Head(ctx, "dir")
	require.NoError(t, err)
	assert.False(t, meta.Exists)

	_, _, err = st.Get(ctx, "dir")
	require.ErrorIs(t, err, domain.ErrNotFound)

	_, _, err = st.GetRange(ctx, "dir", 0, 127)
	require.ErrorIs(t, err, domain.ErrNotFound)
}

func TestContextCancellation(t *testing.T) {
	t.Parallel()
	st, _ := newStore(t)
	put(t, st, "a/b.txt", "data")

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := st.Head(canceled, "a/b.txt")
	require.ErrorIs(t, err, context.Canceled)

	err = st.Put(canceled, "c.txt", strings.NewReader("x"), domain.PutMeta{})
	require.ErrorIs(t, err, context.Canceled)

	_, _, err = st.Get(canceled, "a/b.txt")
	require.ErrorIs(t, err, context.Canceled)

	_, _, err = st.GetRange(canceled, "a/b.txt", 0, 1)
	require.ErrorIs(t, err, context.Canceled)

	err = st.Delete(canceled, "a/b.txt")
	require.ErrorIs(t, err, context.Canceled)

	_, err = st.List(canceled, domain.ListOptions{})
	require.ErrorIs(t, err, context.Canceled)
}

// cancelAfterReader emits single bytes and cancels its context once it has
// been read `after` times, so the store observes cancellation mid-copy.
type cancelAfterReader struct {
	cancel context.CancelFunc
	after  int
	reads  int
}

func (r *cancelAfterReader) Read(p []byte) (int, error) {
	r.reads++
	p[0] = 'x'
	if r.reads >= r.after {
		r.cancel()
	}
	return 1, nil
}

func TestPutAbortsOnContextCancel(t *testing.T) {
	t.Parallel()
	for _, layout := range []string{config.LocalLayoutContainer, config.LocalLayoutRaw} {
		t.Run(layout, func(t *testing.T) {
			t.Parallel()
			st, err := localstore.New(config.LocalConfig{Dir: t.TempDir(), Layout: layout})
			require.NoError(t, err)
			t.Cleanup(func() { _ = st.Close() })

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err = st.Put(ctx, "k.bin",
				&cancelAfterReader{cancel: cancel, after: container.HeaderSize},
				domain.PutMeta{})
			require.ErrorIs(t, err, context.Canceled)
		})
	}
}

func keysOf(page domain.ListPage) []string {
	keys := make([]string, 0, len(page.Contents))
	for _, o := range page.Contents {
		keys = append(keys, o.Key)
	}
	return keys
}
