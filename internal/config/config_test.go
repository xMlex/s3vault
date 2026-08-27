package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDefaults(t *testing.T) {
	t.Parallel()
	v := viper.New()
	SetDefaults(v)
	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Equal(t, "info", cfg.Log.Level)
	assert.Equal(t, 4, cfg.Archive.Workers)
	assert.Equal(t, "overwrite", cfg.Archive.OnChange)
	assert.Equal(t, "none", cfg.Encryption.Mode)
	assert.NotEmpty(t, cfg.Cache.Dir)
	assert.False(t, cfg.Server.S3BucketAsPrefix)
}

func TestLoadInvalidOlderThan(t *testing.T) {
	t.Parallel()
	v := viper.New()
	SetDefaults(v)
	v.Set("archive.older_than", "nope")
	_, err := Load(v)
	require.Error(t, err)
}

func TestFlagOverridesDefault(t *testing.T) {
	t.Parallel()
	v := viper.New()
	SetDefaults(v)
	v.Set("archive.workers", 8)
	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Equal(t, 8, cfg.Archive.Workers)
}

func TestCommandThumbprintFromArgv(t *testing.T) {
	t.Parallel()
	v := viper.New()
	SetDefaults(v)
	v.Set("encryption.mode", "command")
	v.Set("encryption.command.encrypt", []string{"/bin/cryptcp-encrypt", "AF:A4 3C43975FBFC700F051FD62016E1571E7E025"})
	v.Set("encryption.command.decrypt", []string{"/bin/cryptcp-decrypt"})
	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Equal(t, "afa43c43975fbfc700f051fd62016e1571e7e025", cfg.Encryption.Command.Thumbprint)
}

func TestRemoteURLTrim(t *testing.T) {
	t.Parallel()
	v := viper.New()
	SetDefaults(v)
	v.Set("remote.url", "https://s3vault.example:8080/")
	v.Set("remote.rate_limit_bps", int64(1024))
	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Equal(t, "https://s3vault.example:8080", cfg.Remote.URL)
	assert.Equal(t, int64(1024), cfg.Remote.RateLimitBPS)
}

func TestRemoteRateLimitNegative(t *testing.T) {
	t.Parallel()
	v := viper.New()
	SetDefaults(v)
	v.Set("remote.rate_limit_bps", int64(-1))
	_, err := Load(v)
	require.Error(t, err)
}

func TestEnvWithoutYAMLDefault(t *testing.T) {
	// Keys with no SetDefault (e.g. server.token) are invisible to Unmarshal
	// unless BindEnv registered them — the failure mode that rejected
	// S3VAULT_SERVER_TOKEN on non-loopback listen.
	t.Setenv("S3VAULT_SERVER_TOKEN", "env-token")
	t.Setenv("S3VAULT_S3_BUCKET", "env-bucket")
	t.Setenv("S3VAULT_S3_SECRET_KEY", "env-secret")
	t.Setenv("S3VAULT_REMOTE_URL", "https://remote.example:8080/")
	t.Setenv("S3VAULT_SERVER_S3_BUCKET_AS_PREFIX", "true")

	v := viper.New()
	SetDefaults(v)
	v.SetEnvPrefix("S3VAULT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	require.NoError(t, BindEnv(v))
	v.AutomaticEnv()

	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Equal(t, "env-token", cfg.Server.Token)
	assert.Equal(t, "env-bucket", cfg.S3.Bucket)
	assert.Equal(t, "env-secret", cfg.S3.SecretKey)
	assert.Equal(t, "https://remote.example:8080", cfg.Remote.URL)
	assert.True(t, cfg.Server.S3BucketAsPrefix)
}

func TestEnvIgnoredWithoutBindEnv(t *testing.T) {
	t.Setenv("S3VAULT_SERVER_TOKEN", "env-token")

	v := viper.New()
	SetDefaults(v)
	v.SetEnvPrefix("S3VAULT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Empty(t, cfg.Server.Token, "AutomaticEnv alone must not populate Unmarshal for unbound keys")
}
