package spool_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/spool"
)

func TestSweepRemovesOnlyStaleSpoolFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	old := time.Now().Add(-2 * time.Hour)

	write := func(name string, atime time.Time) string {
		t.Helper()

		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
		require.NoError(t, os.Chtimes(path, atime, atime))

		return path
	}

	stalePut := write(spool.PutPrefix+"old", old)
	staleGet := write(spool.GetPrefix+"old", old)
	freshPut := write(spool.PutPrefix+"new", time.Now())
	foreign := write("operator-file", old)

	removed := spool.Sweep(dir, time.Hour)
	assert.Equal(t, 2, removed)

	assert.NoFileExists(t, stalePut)
	assert.NoFileExists(t, staleGet)
	assert.FileExists(t, freshPut)
	assert.FileExists(t, foreign, "unrelated files are not the spool's to delete")
}

func TestSweepDisabled(t *testing.T) {
	t.Parallel()

	assert.Zero(t, spool.Sweep("", time.Hour))
	assert.Zero(t, spool.Sweep(t.TempDir(), 0))
}

func TestCreateUsesPrefix(t *testing.T) {
	t.Parallel()

	f, err := spool.Create(t.TempDir(), spool.GetPrefix)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	assert.Contains(t, filepath.Base(f.Name()), spool.GetPrefix)
}
