package cli

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// run executes the command tree and returns stdout.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, _, err := runWithLogs(t, args...)
	return out, err
}

// runWithLogs also returns the structured log stream (stderr).
func runWithLogs(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	cmd := NewRootCommand(Options{Version: "test", Stdout: out, Stderr: errOut})
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "s3vault-test.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// TestLocalBackendUploadDownload covers the whole pipeline on the local
// filesystem backend: keying, identity, dedup and download. With the default
// encryption.mode=none the object is the bare payload — that is the whole point
// of mode=none, and it applies to the local backend exactly as it does to S3.
func TestLocalBackendUploadDownload(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	objects := filepath.Join(base, "objects")
	cfg := writeConfig(t, base, fmt.Sprintf(`
backend:
  type: local
  local:
    dir: %q
s3:
  prefix: backups
cache:
  dir: %q
`, objects, filepath.Join(base, "cache")))

	src := filepath.Join(base, "app.log")
	payload := []byte("plaintext payload\n")
	require.NoError(t, os.WriteFile(src, payload, 0o600))

	out, err := run(t, "upload", src, "--config", cfg, "--output", "json")
	require.NoError(t, err)
	assert.Contains(t, out, `"uploaded":1`)

	stored := filepath.Join(objects, "backups", "app.log")
	raw, err := os.ReadFile(stored)
	require.NoError(t, err)
	assert.Equal(t, payload, raw, "encryption.mode=none writes the bare payload, no container")

	// Identical content is recognised by content hash, not by ETag.
	out, err = run(t, "upload", src, "--config", cfg, "--output", "json")
	require.NoError(t, err)
	assert.Contains(t, out, `"skipped":1`)
	assert.Contains(t, out, `"uploaded":0`)

	dest := filepath.Join(base, "restored.log")
	_, err = run(t, "download", "backups/app.log", dest, "--config", cfg)
	require.NoError(t, err)
	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// A stale backend.local.layout must be named at startup: viper would ignore it
// and the operator would get a different object shape than their file asks for.
func TestLocalBackendLayoutKeyRemoved(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	cfg := writeConfig(t, base, fmt.Sprintf(`
backend:
  type: local
  local:
    dir: %q
    layout: raw
`, filepath.Join(base, "objects")))

	_, err := run(t, "upload", filepath.Join(base, "any.log"), "--config", cfg)
	require.ErrorContains(t, err, "backend.local.layout")

	_, statErr := os.Stat(filepath.Join(base, "objects", "any.log"))
	assert.True(t, os.IsNotExist(statErr), "nothing may be written when the config is refused")
}

func TestLocalBackendNativeEncryptionRoundtrip(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	objects := filepath.Join(base, "objects")

	kek := make([]byte, 32)
	_, err := rand.Read(kek)
	require.NoError(t, err)
	keyFile := filepath.Join(base, "kek.bin")
	require.NoError(t, os.WriteFile(keyFile, kek, 0o600))

	cfg := writeConfig(t, base, fmt.Sprintf(`
backend:
  type: local
  local:
    dir: %q
encryption:
  mode: native
  native:
    wrap: keyfile
    key_file: %q
    chunk_size: 65536
cache:
  dir: %q
`, objects, keyFile, filepath.Join(base, "cache")))

	src := filepath.Join(base, "secret.log")
	payload := bytes.Repeat([]byte("secret line\n"), 5000)
	require.NoError(t, os.WriteFile(src, payload, 0o600))

	out, err := run(t, "upload", src, "--config", cfg, "--output", "json")
	require.NoError(t, err)
	assert.Contains(t, out, `"uploaded":1`)

	raw, err := os.ReadFile(filepath.Join(objects, "secret.log"))
	require.NoError(t, err)
	assert.Equal(t, "S3VLT01\n", string(raw[128:136]), "payload is the native envelope")
	assert.NotContains(t, string(raw), "secret line", "plaintext must not reach the object")

	dest := filepath.Join(base, "restored.log")
	_, err = run(t, "download", "secret.log", dest, "--config", cfg)
	require.NoError(t, err)
	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// The log must name the object location, so an operator can tell which
// directory (or bucket) a run actually used.
func TestLocalBackendLogsObjectDir(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	objects := filepath.Join(base, "objects")
	cfg := writeConfig(t, base, fmt.Sprintf(`
backend:
  type: local
  local:
    dir: %q
s3:
  prefix: backups
cache:
  dir: %q
`, objects, filepath.Join(base, "cache")))

	src := filepath.Join(base, "app.log")
	require.NoError(t, os.WriteFile(src, []byte("payload"), 0o600))

	_, logs, err := runWithLogs(t, "upload", src, "--config", cfg)
	require.NoError(t, err)
	assert.Contains(t, logs, "object store ready")
	assert.Contains(t, logs, "backend=local")
	assert.Contains(t, logs, "dir="+objects)
	assert.Contains(t, logs, "prefix=backups")
	assert.NotContains(t, logs, "layout=", "the layout switch no longer exists")
}

func TestLocalBackendArchiveRequiresDir(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	cfg := writeConfig(t, base, "backend:\n  type: local\n")

	_, err := run(t, "upload", filepath.Join(base, "any.log"), "--config", cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backend.local.dir")
}
