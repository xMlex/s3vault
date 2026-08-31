package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	t.Parallel()
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	cmd := NewRootCommand(Options{Version: "test-1", Stdout: out, Stderr: errOut})
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{"version"})
	require.NoError(t, cmd.Execute())
	assert.Equal(t, "test-1\n", out.String())
}

func TestArchiveDryRun(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	oldFile := filepath.Join(root, "file1.log")
	require.NoError(t, os.WriteFile(oldFile, []byte("hello"), 0o600))
	old := time.Now().Add(-10 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(oldFile, old, old))

	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	cmd := NewRootCommand(Options{Version: "test", Stdout: out, Stderr: errOut})
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{"archive", root, "--older-than", "7d", "--dry-run", "--output", "json"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"found":1`)
}

func TestUploadDryRun(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	file := filepath.Join(root, "fresh.log")
	require.NoError(t, os.WriteFile(file, []byte("hello"), 0o600))

	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	cmd := NewRootCommand(Options{Version: "test", Stdout: out, Stderr: errOut})
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{"upload", file, "--dry-run", "--output", "json"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), `"found":1`)
	assert.Contains(t, out.String(), `"uploaded":0`)
}

func TestCorruptAutoConfigFallsBackToEnv(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "s3vault.yaml"), []byte("key:\x00value"), 0o600))
	wd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(wd) })

	t.Setenv("S3VAULT_REMOTE_URL", "http://remote.example")
	t.Setenv("S3VAULT_SERVER_TOKEN", "token")

	root := t.TempDir()
	file := filepath.Join(root, "a.log")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	old := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(file, old, old))

	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	r, w, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	oldStderr := os.Stderr
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = oldStderr
		_ = w.Close()
	})

	cmd := NewRootCommand(Options{Version: "test", Stdout: out, Stderr: errOut})
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{"archive", root, "--older-than", "1h", "--dry-run"})
	require.NoError(t, cmd.Execute())
	require.NoError(t, w.Close())
	var stderr bytes.Buffer
	_, _ = io.Copy(&stderr, r)
	assert.Contains(t, stderr.String(), filepath.Join(dir, "s3vault.yaml"))
}

func TestCorruptExplicitConfigShowsPath(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte("key:\x00value"), 0o600))

	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	cmd := NewRootCommand(Options{Version: "test", Stdout: out, Stderr: errOut})
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{"--config", cfg, "version"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), cfg)
}

func TestBinaryNamedS3VaultIsNotConfig(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "s3vault"), []byte{0x7f, 'E', 'L', 'F'}, 0o755))
	wd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(wd) })

	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	cmd := NewRootCommand(Options{Version: "test", Stdout: out, Stderr: errOut})
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{"version"})
	require.NoError(t, cmd.Execute())
	assert.Empty(t, errOut.String())
}
