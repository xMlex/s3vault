package encrypt

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/config"
)

// writeThumbprintScript installs a script that echoes $CRYPTOPRO_THUMBPRINT.
// The file is written to a temp name and renamed so the path handed to execve
// is never still open for writing — otherwise a parallel test can hit ETXTBSY.
func writeThumbprintScript(t *testing.T, dir string) string {
	t.Helper()

	script := filepath.Join(dir, "echo-tp.sh")
	tmp := script + ".tmp"
	require.NoError(t, os.WriteFile(tmp, []byte("#!/bin/sh\nprintf '%s' \"$CRYPTOPRO_THUMBPRINT\"\n"), 0o700)) //nolint:gosec // test fixture must be executable
	require.NoError(t, os.Rename(tmp, script))

	return script
}

func TestCommandDecryptUsesContextThumbprint(t *testing.T) {
	t.Parallel()
	script := writeThumbprintScript(t, t.TempDir())

	cfgTP := "1111111111111111111111111111111111111111"
	metaTP := "2222222222222222222222222222222222222222"
	c, err := NewCommand(config.CommandEnc{
		Encrypt:    []string{script},
		Decrypt:    []string{script},
		Thumbprint: cfgTP,
	})
	require.NoError(t, err)
	assert.Equal(t, cfgTP, c.CryptoProThumbprint())

	var out bytes.Buffer

	ctx := WithCryptoProThumbprint(context.Background(), metaTP)

	require.NoError(t, c.Decrypt(ctx, &out, bytes.NewReader(nil)))
	assert.Equal(t, metaTP, out.String())
}

func TestCommandEncryptSetsConfigThumbprintEnv(t *testing.T) {
	t.Parallel()
	script := writeThumbprintScript(t, t.TempDir())

	tp := "afa43c43975fbfc700f051fd62016e1571e7e025"
	c, err := NewCommand(config.CommandEnc{
		Encrypt: []string{script, tp},
		Decrypt: []string{script},
	})
	require.NoError(t, err)
	assert.Equal(t, tp, c.CryptoProThumbprint())

	var out bytes.Buffer
	require.NoError(t, c.Encrypt(context.Background(), &out, bytes.NewReader(nil)))
	assert.Equal(t, tp, out.String())
}
