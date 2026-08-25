package cli

import (
	"bytes"
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
