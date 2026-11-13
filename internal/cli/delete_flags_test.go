package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A destructive switch set in config/env must be overridable by the CLI flag
// in both directions: `--delete-after-upload=false` with
// `archive.delete_after_upload: true` used to compute `false || true == true`
// and delete the files the operator explicitly asked to keep (problems.md D4).
func TestArchiveDeleteFlagsOverrideConfig(t *testing.T) {
	t.Parallel()

	newEnv := func(t *testing.T) (cfg, src, objects string) {
		t.Helper()
		base := t.TempDir()
		objects = filepath.Join(base, "objects")
		cfg = writeConfig(t, base, "backend:\n  type: local\n  local:\n    dir: "+objects+"\narchive:\n  delete_after_upload: true\n  delete_if_exists: true\n")
		src = filepath.Join(base, "app.log")
		require.NoError(t, os.WriteFile(src, []byte("payload\n"), 0o600))

		old := time.Now().Add(-10 * 24 * time.Hour)
		require.NoError(t, os.Chtimes(src, old, old))

		return cfg, src, objects
	}

	t.Run("explicit false wins over config true", func(t *testing.T) {
		t.Parallel()
		cfg, src, _ := newEnv(t)

		out, err := run(t, "archive", filepath.Dir(src), "--config", cfg, "--older-than", "7d", "--delete-after-upload=false", "--delete-if-exists=false", "--output", "json")
		require.NoError(t, err)
		assert.Contains(t, out, `"uploaded":1`)

		_, statErr := os.Stat(src)
		require.NoError(t, statErr, "the file the operator kept with an explicit false must survive")
	})

	t.Run("explicit true still deletes", func(t *testing.T) {
		t.Parallel()
		cfg, src, _ := newEnv(t)

		out, err := run(t, "archive", filepath.Dir(src), "--config", cfg, "--older-than", "7d", "--delete-after-upload", "--output", "json")
		require.NoError(t, err)
		assert.Contains(t, out, `"uploaded":1`)

		_, statErr := os.Stat(src)
		require.ErrorIs(t, statErr, os.ErrNotExist, "an explicit true must keep deleting after upload")
	})
}

func TestUploadDeleteFlagsOverrideConfig(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	objects := filepath.Join(base, "objects")
	cfg := writeConfig(t, base, "backend:\n  type: local\n  local:\n    dir: "+objects+"\narchive:\n  delete_after_upload: true\n")
	src := filepath.Join(base, "u.log")
	require.NoError(t, os.WriteFile(src, []byte("payload\n"), 0o600))

	// First upload with the explicit keep-flag: config says delete, flag says no.
	out, err := run(t, "upload", src, "--config", cfg, "--delete-after-upload=false", "--output", "json")
	require.NoError(t, err)
	assert.Contains(t, out, `"uploaded":1`)

	_, statErr := os.Stat(src)
	require.NoError(t, statErr, "upload --delete-after-upload=false must override archive.delete_after_upload: true")

	// Second upload: remote is identical → skip. Config keeps delete_if_exists
	// unset, so the file must still be there.
	out, err = run(t, "upload", src, "--config", cfg, "--output", "json")
	require.NoError(t, err)
	assert.Contains(t, out, `"skipped":1`)

	_, statErr = os.Stat(src)
	require.NoError(t, statErr)
}
