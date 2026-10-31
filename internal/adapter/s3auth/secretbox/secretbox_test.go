package secretbox

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) []byte {
	t.Helper()

	key, err := ParseKey(base64.StdEncoding.EncodeToString(make([]byte, KeySize)))
	require.NoError(t, err)

	return key
}

func TestSealOpen(t *testing.T) {
	t.Parallel()

	key := testKey(t)

	nonce, ciphertext, err := Seal(key, []byte("s3-secret"), "AKIA")
	require.NoError(t, err)
	require.Len(t, nonce, NonceSize)

	got, err := Open(key, nonce, ciphertext, "AKIA")
	require.NoError(t, err)
	assert.Equal(t, "s3-secret", string(got))

	_, err = Open(key, nonce, ciphertext, "OTHER")
	require.ErrorIs(t, err, ErrOpen)

	ciphertext[0] ^= 0xff
	_, err = Open(key, nonce, ciphertext, "AKIA")
	require.ErrorIs(t, err, ErrOpen)
}

func TestParseKey(t *testing.T) {
	t.Parallel()

	_, err := ParseKey("")
	require.Error(t, err)

	_, err = ParseKey(base64.StdEncoding.EncodeToString([]byte("short")))
	require.Error(t, err)

	_, err = ParseKey("not-base64")
	require.Error(t, err)
}

func TestGenerateSecret(t *testing.T) {
	t.Parallel()

	first, err := GenerateSecret()
	require.NoError(t, err)
	second, err := GenerateSecret()
	require.NoError(t, err)

	assert.Len(t, first, 40)
	assert.NotEqual(t, first, second)
}

func TestGenerateKey(t *testing.T) {
	t.Parallel()

	encoded, err := GenerateKey()
	require.NoError(t, err)

	key, err := ParseKey(encoded)
	require.NoError(t, err)
	assert.Len(t, key, KeySize)
}
