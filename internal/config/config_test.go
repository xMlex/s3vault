package config

import (
	"path/filepath"
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
	assert.False(t, cfg.Cache.Enabled)
	assert.False(t, cfg.Server.S3BucketAsPrefix)
	assert.Equal(t, BackendS3, cfg.Backend.Type)
}

func TestBackendLocal(t *testing.T) {
	t.Parallel()
	v := viper.New()
	SetDefaults(v)
	v.Set("backend.type", " LOCAL ")
	v.Set("backend.local.dir", "objects")
	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Equal(t, BackendLocal, cfg.Backend.Type)
	assert.Equal(t, LocalLayoutContainer, cfg.Backend.Local.Layout)
	assert.True(t, filepath.IsAbs(cfg.Backend.Local.Dir), "dir is resolved to an absolute path")
	assert.Equal(t, "local:"+cfg.Backend.Local.Dir, cfg.CacheNamespace())
}

func TestBackendLocalRawLayout(t *testing.T) {
	t.Parallel()
	v := viper.New()
	SetDefaults(v)
	v.Set("backend.type", "local")
	v.Set("backend.local.dir", "objects")
	v.Set("backend.local.layout", " RAW ")
	v.Set("encryption.mode", "none")
	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Equal(t, LocalLayoutRaw, cfg.Backend.Local.Layout)
}

func TestBackendLocalRawRequiresNoEncryption(t *testing.T) {
	t.Parallel()
	v := viper.New()
	SetDefaults(v)
	v.Set("backend.type", "local")
	v.Set("backend.local.dir", "objects")
	v.Set("backend.local.layout", "raw")
	v.Set("encryption.mode", "native")
	_, err := Load(v)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "layout")
}

func TestBackendInvalid(t *testing.T) {
	t.Parallel()
	tests := map[string]map[string]any{
		"unknown type":         {"backend.type": "gcs"},
		"local without dir":    {"backend.type": "local"},
		"unknown local layout": {"backend.type": "local", "backend.local.dir": "objects", "backend.local.layout": "mirror"},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := viper.New()
			SetDefaults(v)
			for key, val := range values {
				v.Set(key, val)
			}
			_, err := Load(v)
			require.Error(t, err)
		})
	}
}

func TestCacheEnabled(t *testing.T) {
	t.Parallel()
	v := viper.New()
	SetDefaults(v)
	v.Set("cache.enabled", true)
	cfg, err := Load(v)
	require.NoError(t, err)
	assert.True(t, cfg.Cache.Enabled)
}

func TestCacheNamespaceS3(t *testing.T) {
	t.Parallel()
	v := viper.New()
	SetDefaults(v)
	v.Set("s3.bucket", "my-bucket")
	v.Set("s3.prefix", "backups")
	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Equal(t, "my-bucket", cfg.CacheNamespace())
	assert.Equal(t, "backups", cfg.KeyPrefix())
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
	t.Setenv("S3VAULT_BACKEND_TYPE", "local")
	t.Setenv("S3VAULT_BACKEND_LOCAL_DIR", "/srv/s3vault/objects")

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
	assert.Equal(t, BackendLocal, cfg.Backend.Type)
	assert.Equal(t, "/srv/s3vault/objects", cfg.Backend.Local.Dir)
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
