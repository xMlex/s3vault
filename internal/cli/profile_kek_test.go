package cli

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadProfileKEK(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("S3VAULT_TEST_PROFILE_KEK", hex.EncodeToString(key))

	got, err := readProfileKEK("S3VAULT_TEST_PROFILE_KEK",
		json.RawMessage(`{"mode":"native","native":{"wrap":"keyfile"}}`))
	require.NoError(t, err)
	assert.Equal(t, key, got)
}

func TestReadProfileKEKRejectsOtherModes(t *testing.T) {
	t.Setenv("S3VAULT_TEST_PROFILE_KEK", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	_, err := readProfileKEK("S3VAULT_TEST_PROFILE_KEK", json.RawMessage(`{"mode":"none"}`))
	require.ErrorContains(t, err, "requires mode=native")
}

func TestReadProfileKEKRejectsNamedSource(t *testing.T) {
	t.Setenv("S3VAULT_TEST_PROFILE_KEK", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	_, err := readProfileKEK("S3VAULT_TEST_PROFILE_KEK",
		json.RawMessage(`{"mode":"native","native":{"wrap":"keyfile","key_env":"OTHER"}}`))
	require.ErrorContains(t, err, "exclusive")
}

func TestReadProfileKEKNeedsEnv(t *testing.T) {
	t.Parallel()

	_, err := readProfileKEK("S3VAULT_TEST_PROFILE_KEK_MISSING",
		json.RawMessage(`{"mode":"native","native":{"wrap":"keyfile"}}`))
	require.ErrorContains(t, err, "is not set")
}
