package encrypt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/config"
)

func testResolver(t *testing.T, cfg config.EncryptionConfig) (*Resolver, string) {
	t.Helper()

	resolver, err := NewResolver(cfg)
	require.NoError(t, err)

	return resolver, resolver.Default().Fingerprint
}

func keyFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "kek.bin")
	require.NoError(t, os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef"), 0o600))

	return path
}

func TestResolverDefault(t *testing.T) {
	t.Parallel()

	resolver, fp := testResolver(t, config.EncryptionConfig{Mode: NameNone})

	profile, err := resolver.ResolveRaw(nil)
	require.NoError(t, err)
	assert.Equal(t, NameNone, Name(profile.Primary))
	assert.Nil(t, profile.Fallback)
	assert.Equal(t, fp, profile.Fingerprint)

	for _, raw := range []string{"{}", "null", `{"mode":""}`, `{"mode":" "}`} {
		profile, err := resolver.ResolveRaw(json.RawMessage(raw))
		require.NoError(t, err)
		assert.Equal(t, fp, profile.Fingerprint, raw)
	}
}

func TestResolverNativeKeyfile(t *testing.T) {
	t.Parallel()

	path := keyFile(t)
	resolver, fp := testResolver(t, config.EncryptionConfig{Mode: NameNone})

	raw := json.RawMessage(`{
		"mode": "native",
		"native": {"wrap": "keyfile", "key_file": "` + path + `", "chunk_size": 4096}
	}`)
	profile, err := resolver.ResolveRaw(raw)
	require.NoError(t, err)
	assert.Equal(t, NameNative, Name(profile.Primary))
	require.NotNil(t, profile.Fallback)
	assert.Equal(t, NameNone, Name(profile.Fallback))
	assert.NotEqual(t, fp, profile.Fingerprint)
}

func TestResolverSameModeHasNoFallback(t *testing.T) {
	t.Parallel()

	path := keyFile(t)
	cfg := config.EncryptionConfig{
		Mode: NameNative,
		Native: config.NativeEnc{
			Wrap:    WrapKeyfile,
			KeyFile: path,
		},
	}
	resolver, _ := testResolver(t, cfg)

	profile, err := resolver.ResolveRaw(json.RawMessage(`{
		"mode": "native",
		"native": {"wrap": "keyfile", "key_file": "` + path + `"}
	}`))
	require.NoError(t, err)
	assert.Equal(t, NameNative, Name(profile.Primary))
	assert.Nil(t, profile.Fallback)
}

func TestResolverCommand(t *testing.T) {
	t.Parallel()

	resolver, _ := testResolver(t, config.EncryptionConfig{Mode: NameNone})

	profile, err := resolver.ResolveRaw(json.RawMessage(`{
		"mode": "command",
		"command": {
			"encrypt": ["/bin/true"],
			"decrypt": ["/bin/true"],
			"thumbprint": "afa43c43975fbfc700f051fd62016e1571e7e025",
			"timeout": "1m"
		}
	}`))
	require.NoError(t, err)
	assert.Equal(t, NameCommand, Name(profile.Primary))
	require.NotNil(t, profile.Fallback)
	assert.Equal(t, NameNone, Name(profile.Fallback))
}

func TestResolverRejectsInvalidProfiles(t *testing.T) {
	t.Parallel()

	resolver, _ := testResolver(t, config.EncryptionConfig{Mode: NameNone})

	tests := []struct {
		name string
		raw  string
	}{
		{name: "unknown field", raw: `{"mode":"none","extra":1}`},
		{name: "unknown mode", raw: `{"mode":"aes"}`},
		{name: "native without key", raw: `{"mode":"native","native":{"wrap":"keyfile"}}`},
		{name: "command without argv", raw: `{"mode":"command","command":{"thumbprint":"afa43c43975fbfc700f051fd62016e1571e7e025"}}`},
		{name: "command without thumbprint", raw: `{"mode":"command","command":{"encrypt":["/bin/true"],"decrypt":["/bin/true"]}}`},
		{name: "bad timeout", raw: `{"mode":"command","command":{"encrypt":["/bin/true"],"decrypt":["/bin/true"],"thumbprint":"afa43c43975fbfc700f051fd62016e1571e7e025","timeout":"soon"}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := resolver.ResolveRaw(json.RawMessage(tt.raw))
			require.Error(t, err)
		})
	}
}

func TestName(t *testing.T) {
	t.Parallel()

	assert.Equal(t, NameNone, Name(Passthrough{}))
}
