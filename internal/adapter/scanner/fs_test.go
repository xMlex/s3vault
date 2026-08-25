package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/scanner"
	"github.com/xMlex/s3vault/internal/domain"
)

func TestFSScanOlderThan(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	oldFile := filepath.Join(root, "file1.log")
	newFile := filepath.Join(root, "file2.log")
	nested := filepath.Join(root, "logs", "file3.log")
	require.NoError(t, os.MkdirAll(filepath.Dir(nested), 0o700))
	require.NoError(t, os.WriteFile(oldFile, []byte("a"), 0o600))
	require.NoError(t, os.WriteFile(newFile, []byte("b"), 0o600))
	require.NoError(t, os.WriteFile(nested, []byte("c"), 0o600))

	old := time.Now().Add(-10 * 24 * time.Hour)
	recent := time.Now().Add(-2 * 24 * time.Hour)
	veryOld := time.Now().Add(-30 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(oldFile, old, old))
	require.NoError(t, os.Chtimes(newFile, recent, recent))
	require.NoError(t, os.Chtimes(nested, veryOld, veryOld))

	s := scanner.New(scanner.Options{})
	var found []string
	for info, err := range s.Scan(context.Background(), root, 7*24*time.Hour) {
		require.NoError(t, err)
		found = append(found, info.RelPath)
	}

	assert.ElementsMatch(t, []string{"file1.log", "logs/file3.log"}, found)
}

func TestFSScanSkipsSymlinkByDefault(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "real.log")
	link := filepath.Join(root, "link.log")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0o600))
	old := time.Now().Add(-10 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(target, old, old))
	require.NoError(t, os.Symlink(target, link))

	s := scanner.New(scanner.Options{})
	var found []domain.FileInfo
	for info, err := range s.Scan(context.Background(), root, time.Hour) {
		require.NoError(t, err)
		found = append(found, info)
	}

	require.Len(t, found, 1)
	assert.Equal(t, "real.log", found[0].RelPath)
}

func TestFSStat(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	file := filepath.Join(root, "a.log")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	link := filepath.Join(root, "link.log")
	require.NoError(t, os.Symlink(file, link))

	s := scanner.New(scanner.Options{})
	info, err := s.Stat(root, file)
	require.NoError(t, err)
	assert.Equal(t, "a.log", info.RelPath)

	_, err = s.Stat(root, link)
	require.ErrorIs(t, err, domain.ErrSymlinkSkipped)

	_, err = s.Stat(root, root)
	require.ErrorIs(t, err, domain.ErrNotRegularFile)

	follow := scanner.New(scanner.Options{FollowSymlinks: true})
	info, err = follow.Stat(root, link)
	require.NoError(t, err)
	assert.Equal(t, "link.log", info.RelPath)
}
