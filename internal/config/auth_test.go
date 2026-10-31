// Package config tests the server.auth configuration surface.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeAuthDefaults(t *testing.T) {
	t.Parallel()

	var c Config
	require.NoError(t, c.normalizeAuth())
	assert.Equal(t, AuthBackendStatic, c.Server.Auth.Backend)
	assert.Equal(t, DefaultAuthMaxConns, c.Server.Auth.MaxConns)
	assert.Equal(t, DefaultAuthQueryTimeout, c.Server.Auth.QueryTimeout)
	assert.Equal(t, DefaultAuthTargetPoolMax, c.Server.Auth.TargetPoolMax)
	assert.Equal(t, DefaultAuthTargetPoolIdle, c.Server.Auth.TargetPoolIdle)
}

func TestNormalizeAuthPostgres(t *testing.T) {
	t.Parallel()

	c := Config{}
	c.Server.Auth.Backend = AuthBackendPostgres
	c.Server.Auth.DSN = "postgres://localhost/db"
	require.NoError(t, c.normalizeAuth())
	assert.Equal(t, AuthBackendPostgres, c.Server.Auth.Backend)

	c.Server.S3AccessKey = "key"
	err := c.normalizeAuth()
	require.ErrorContains(t, err, "must be empty")

	c.Server.S3AccessKey = ""
	c.Server.S3SecretKey = ""
	c.Server.S3BucketAsPrefix = true
	err = c.normalizeAuth()
	require.ErrorContains(t, err, "s3_bucket_as_prefix")

	c.Server.S3BucketAsPrefix = false
	c.Server.Auth.DSN = ""
	err = c.normalizeAuth()
	require.ErrorContains(t, err, "server.auth.dsn")
}

func TestNormalizeAuthRejectsUnknownBackend(t *testing.T) {
	t.Parallel()

	c := Config{}
	c.Server.Auth.Backend = "postgresql"

	err := c.normalizeAuth()
	require.ErrorContains(t, err, "unknown value")
}

func TestNormalizeAuthBounds(t *testing.T) {
	t.Parallel()

	c := Config{}
	c.Server.Auth.MaxConns = -1
	require.Error(t, c.normalizeAuth())

	c = Config{}
	c.Server.Auth.QueryTimeout = -time.Second
	require.Error(t, c.normalizeAuth())

	c = Config{}
	c.Server.Auth.TargetPoolMax = -1
	require.ErrorContains(t, c.normalizeAuth(), "target_pool_max")

	c = Config{}
	c.Server.Auth.TargetPoolIdle = -time.Second
	require.ErrorContains(t, c.normalizeAuth(), "target_pool_idle")
}

func TestAuthFromEnv(t *testing.T) {
	t.Setenv("S3VAULT_SERVER_AUTH_BACKEND", "postgres")
	t.Setenv("S3VAULT_SERVER_AUTH_DSN", "postgres://localhost/db")
	t.Setenv("S3VAULT_SERVER_AUTH_MAX_CONNS", "12")
	t.Setenv("S3VAULT_SERVER_AUTH_QUERY_TIMEOUT", "3s")
	t.Setenv("S3VAULT_SERVER_AUTH_TARGET_POOL_MAX", "16")
	t.Setenv("S3VAULT_SERVER_AUTH_TARGET_POOL_IDLE", "5m")
	t.Setenv("S3VAULT_SERVER_S3_ACCESS_KEY", "")
	t.Setenv("S3VAULT_SERVER_S3_SECRET_KEY", "")

	v := viper.New()
	SetDefaults(v)
	v.SetEnvPrefix("S3VAULT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()
	require.NoError(t, BindEnv(v))

	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Equal(t, AuthBackendPostgres, cfg.Server.Auth.Backend)
	assert.Equal(t, int32(12), cfg.Server.Auth.MaxConns)
	assert.Equal(t, 3*time.Second, cfg.Server.Auth.QueryTimeout)
	assert.Equal(t, 16, cfg.Server.Auth.TargetPoolMax)
	assert.Equal(t, 5*time.Minute, cfg.Server.Auth.TargetPoolIdle)
}

func TestSecretsInPlainConfigWarnsOnDSNPassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dsn  string
		want bool
	}{
		{name: "no password", dsn: "postgres://s3vault@127.0.0.1:5432/s3vault?sslmode=disable"},
		{name: "password", dsn: "postgres://s3vault:secret@127.0.0.1:5432/s3vault?sslmode=disable", want: true}, //nolint:gosec // test fixture, not a real credential
		{name: "empty password", dsn: "postgres://s3vault:@127.0.0.1:5432/s3vault", want: true},
		{name: "invalid dsn", dsn: "not a dsn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "config.yaml")
			body := fmt.Sprintf("server:\n  auth:\n    dsn: %q\n", tt.dsn)
			require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

			v := viper.New()
			v.SetConfigFile(path)
			require.NoError(t, v.ReadInConfig())

			assert.Equal(t, tt.want, SecretsInPlainConfig(v))
		})
	}
}

func TestS3APIEnabled(t *testing.T) {
	t.Parallel()

	assert.False(t, ServerConfig{}.S3APIEnabled())
	assert.True(t, ServerConfig{S3AccessKey: "a", S3SecretKey: "b"}.S3APIEnabled())
	assert.True(t, ServerConfig{Auth: ServerAuthConfig{Backend: AuthBackendPostgres}}.S3APIEnabled())
}
