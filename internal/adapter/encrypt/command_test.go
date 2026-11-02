package encrypt

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/config"
)

// thumbprintArgv runs a shell that prints CRYPTOPRO_THUMBPRINT. No executable
// file is written: a freshly written script can hit ETXTBSY when a parallel
// test forks while the file is still open for writing.
func thumbprintArgv(extra ...string) []string {
	argv := []string{"/bin/sh", "-c", `printf '%s' "$CRYPTOPRO_THUMBPRINT"`}
	return append(argv, extra...)
}

func TestCommandDecryptUsesContextThumbprint(t *testing.T) {
	t.Parallel()

	cfgTP := "1111111111111111111111111111111111111111"
	metaTP := "2222222222222222222222222222222222222222"
	c, err := NewCommand(config.CommandEnc{
		Encrypt:    thumbprintArgv(),
		Decrypt:    thumbprintArgv(),
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

	tp := "afa43c43975fbfc700f051fd62016e1571e7e025"
	c, err := NewCommand(config.CommandEnc{
		Encrypt: thumbprintArgv(tp),
		Decrypt: thumbprintArgv(),
	})
	require.NoError(t, err)
	assert.Equal(t, tp, c.CryptoProThumbprint())

	var out bytes.Buffer
	require.NoError(t, c.Encrypt(context.Background(), &out, bytes.NewReader(nil)))
	assert.Equal(t, tp, out.String())
}
