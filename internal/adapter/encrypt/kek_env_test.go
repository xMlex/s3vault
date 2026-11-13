package encrypt

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/config"
)

func TestParseKEKEnv(t *testing.T) {
	t.Parallel()

	key := []byte("0123456789abcdef0123456789abcdef")

	t.Run("base64", func(t *testing.T) {
		t.Parallel()

		got, err := ParseKEKEnv(base64.StdEncoding.EncodeToString(key))
		require.NoError(t, err)
		assert.Equal(t, key, got)
	})

	t.Run("hex", func(t *testing.T) {
		t.Parallel()

		got, err := ParseKEKEnv(hex.EncodeToString(key))
		require.NoError(t, err)
		assert.Equal(t, key, got)
	})

	t.Run("wrong length", func(t *testing.T) {
		t.Parallel()

		_, err := ParseKEKEnv("not-a-key")
		require.Error(t, err)
	})
}

// An empty (or blank) key file would hash into sha256(""), a publicly known
// KEK: every deployment that lost its key material to a truncated mount would
// silently share one key. A readable-but-empty file must fail, not fall back.
func TestLoadKEKRejectsEmptyKeyFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "kek.bin")

	require.NoError(t, os.WriteFile(path, nil, 0o600))
	_, err := loadKEK(config.NativeEnc{KeyFile: path})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")

	require.NoError(t, os.WriteFile(path, []byte("\n\t "), 0o600))
	_, err = loadKEK(config.NativeEnc{KeyFile: path})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestLoadKEKPrefersReadableFile(t *testing.T) {
	envKey := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	fileKey := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	path := filepath.Join(t.TempDir(), "kek.bin")
	require.NoError(t, os.WriteFile(path, fileKey, 0o600))
	t.Setenv("S3VAULT_TEST_KEK", base64.StdEncoding.EncodeToString(envKey))

	got, err := loadKEK(config.NativeEnc{KeyFile: path, KeyEnv: "S3VAULT_TEST_KEK"})
	require.NoError(t, err)
	assert.Equal(t, fileKey, got)
}

func TestLoadKEKFallsBackToEnv(t *testing.T) {
	envKey := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	t.Setenv("S3VAULT_TEST_KEK", base64.StdEncoding.EncodeToString(envKey))

	got, err := loadKEK(config.NativeEnc{
		KeyFile: filepath.Join(t.TempDir(), "missing.kek"),
		KeyEnv:  "S3VAULT_TEST_KEK",
	})
	require.NoError(t, err)
	assert.Equal(t, envKey, got)
}

func TestLoadKEKUsesDefaultEnv(t *testing.T) {
	envKey := []byte("cccccccccccccccccccccccccccccccc")
	t.Setenv(config.DefaultNativeKeyEnv, hex.EncodeToString(envKey))

	got, err := loadKEK(config.NativeEnc{})
	require.NoError(t, err)
	assert.Equal(t, envKey, got)
}

func TestLoadKEKSealedKeyWins(t *testing.T) {
	sealed := []byte("dddddddddddddddddddddddddddddddd")

	t.Setenv(config.DefaultNativeKeyEnv, base64.StdEncoding.EncodeToString([]byte("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")))

	got, err := loadKEK(config.NativeEnc{Key: sealed})
	require.NoError(t, err)
	assert.Equal(t, sealed, got)
}

func TestFingerprintTracksEnvKEKRotation(t *testing.T) {
	cfg := config.EncryptionConfig{
		Mode:   NameNative,
		Native: config.NativeEnc{Wrap: WrapKeyfile, KeyEnv: "S3VAULT_TEST_ROTATE"},
	}

	t.Setenv("S3VAULT_TEST_ROTATE", base64.StdEncoding.EncodeToString([]byte("11111111111111111111111111111111")))

	first := Fingerprint(cfg)

	t.Setenv("S3VAULT_TEST_ROTATE", base64.StdEncoding.EncodeToString([]byte("22222222222222222222222222222222")))

	second := Fingerprint(cfg)

	assert.NotEqual(t, first, second)
}
