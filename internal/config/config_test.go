package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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
	assert.Equal(t, "none", cfg.Encryption.Mode)
	assert.NotEmpty(t, cfg.Cache.Dir)
	assert.False(t, cfg.Cache.Enabled)
	assert.False(t, cfg.Server.S3BucketAsPrefix)
	assert.Equal(t, BackendS3, cfg.Backend.Type)
	assert.Equal(t, 24*time.Hour, cfg.Server.MultipartTTL)
	assert.Equal(t, 15*time.Minute, cfg.Server.MultipartSweepInterval)
	assert.Equal(t, 64, cfg.Server.MultipartMaxSessions)
	assert.Zero(t, cfg.Server.MultipartMaxBytes, "no per-session spool budget unless asked for")
	assert.Equal(t, DefaultMultipartPartSize, cfg.S3.MultipartPartSize)
}

// The part size is bounded by S3 on both sides. The bounds are checked in
// Normalize rather than left to the SDK, which would only complain about a
// too-small value at the first upload, naming neither the key nor the reason.
// Zero is the single exception: it means "not specified" and takes the default,
// the same way archive.workers below 1 is clamped rather than refused.
func TestMultipartPartSizeBounds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		partSize int64
		want     int64
		wantErr  string
	}{
		{name: "zero means unset", partSize: 0, want: DefaultMultipartPartSize},
		{name: "negative", partSize: -1, wantErr: "s3.multipart_part_size"},
		{name: "one byte", partSize: 1, wantErr: "s3.multipart_part_size"},
		{name: "just under the S3 minimum", partSize: MinMultipartPartSize - 1, wantErr: "at least 5242880"},
		{name: "exactly the S3 minimum", partSize: MinMultipartPartSize, want: MinMultipartPartSize},
		{name: "exactly the S3 maximum", partSize: MaxMultipartPartSize, want: MaxMultipartPartSize},
		{name: "just over the S3 maximum", partSize: MaxMultipartPartSize + 1, wantErr: "at most 5368709120"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			v := viper.New()
			SetDefaults(v)
			v.Set("s3.multipart_part_size", tc.partSize)
			cfg, err := Load(v)

			if tc.wantErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.want, cfg.S3.MultipartPartSize)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// The key is advertised in .env.example, so it must bind — the same failure
// TestEnvKeysMatchConfigFields exists for.
func TestMultipartPartSizeFromEnv(t *testing.T) {
	t.Setenv("S3VAULT_S3_MULTIPART_PART_SIZE", "52428800")

	v := viper.New()
	SetDefaults(v)
	v.SetEnvPrefix("S3VAULT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()
	require.NoError(t, BindEnv(v))

	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Equal(t, int64(52428800), cfg.S3.MultipartPartSize)
}

// The multipart spool defaults beside the cache directory but is not inside it:
// the cache carries its own invariants (TTL, sweeper, lockfile) and can be
// switched off, while multipart has to work in every configuration. Reusing
// cache.dir would have coupled a must-always-work feature to a default-false one.
func TestMultipartDirDefault(t *testing.T) {
	t.Parallel()

	t.Run("derived from cache.dir", func(t *testing.T) {
		t.Parallel()

		v := viper.New()
		SetDefaults(v)
		v.Set("cache.dir", "/srv/s3vault/cache")
		cfg, err := Load(v)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join("/srv/s3vault/cache", "multipart"), cfg.Server.MultipartDir)
	})

	t.Run("overridable", func(t *testing.T) {
		t.Parallel()

		v := viper.New()
		SetDefaults(v)
		v.Set("cache.dir", "/srv/s3vault/cache")
		v.Set("server.multipart_dir", "/srv/s3vault/mp")
		cfg, err := Load(v)
		require.NoError(t, err)
		assert.Equal(t, "/srv/s3vault/mp", cfg.Server.MultipartDir)
	})
}

// The spool keys are advertised in .env.example, so they must actually bind —
// this is the same failure TestEnvKeysMatchConfigFields was written for (a key
// that looks wired while nothing reads it).
func TestMultipartKeysFromEnv(t *testing.T) {
	t.Setenv("S3VAULT_SERVER_MULTIPART_DIR", "/tmp/mp")
	t.Setenv("S3VAULT_SERVER_MULTIPART_TTL", "90m")
	t.Setenv("S3VAULT_SERVER_MULTIPART_SWEEP_INTERVAL", "5m")
	t.Setenv("S3VAULT_SERVER_MULTIPART_MAX_SESSIONS", "7")
	t.Setenv("S3VAULT_SERVER_MULTIPART_MAX_BYTES", "1048576")

	v := viper.New()
	SetDefaults(v)
	v.SetEnvPrefix("S3VAULT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()
	require.NoError(t, BindEnv(v))

	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Equal(t, "/tmp/mp", cfg.Server.MultipartDir)
	assert.Equal(t, 90*time.Minute, cfg.Server.MultipartTTL)
	assert.Equal(t, 5*time.Minute, cfg.Server.MultipartSweepInterval)
	assert.Equal(t, 7, cfg.Server.MultipartMaxSessions)
	assert.Equal(t, int64(1048576), cfg.Server.MultipartMaxBytes)
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
	assert.True(t, filepath.IsAbs(cfg.Backend.Local.Dir), "dir is resolved to an absolute path")
	assert.Equal(t, "local:"+cfg.Backend.Local.Dir, cfg.CacheNamespace())
}

// backend.local.layout is gone: encryption.mode alone decides the object shape.
// A stale key would be ignored by viper, so it must be named at startup instead
// of silently changing what gets written.
func TestBackendLocalLayoutRemoved(t *testing.T) {
	t.Parallel()

	v := viper.New()
	SetDefaults(v)
	v.Set("backend.type", "local")
	v.Set("backend.local.dir", "objects")
	v.Set("backend.local.layout", "raw")

	_, err := Load(v)
	require.ErrorContains(t, err, "backend.local.layout")
	require.ErrorContains(t, err, "encryption.mode=none writes the bare payload")
}

func TestBackendInvalid(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string]any{
		"unknown type":      {"backend.type": "gcs"},
		"local without dir": {"backend.type": "local"},
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

func TestRemovedKeysRejected(t *testing.T) {
	t.Parallel()

	tests := map[string]map[string]any{
		"remote.url":        {"remote.url": "https://s3vault.example:8080"},
		"remote.rate_limit": {"remote.rate_limit_bps": int64(1024)},
		"server.token":      {"server.token": "secret"},
		"archive.on_change": {"archive.on_change": "skip"},
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
			assert.Contains(t, err.Error(), "was removed")
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

func TestEnvWithoutYAMLDefault(t *testing.T) {
	// Keys with no SetDefault (e.g. s3.secret_key, backend.local.dir) are
	// invisible to Unmarshal unless BindEnv registered them.
	t.Setenv("S3VAULT_S3_BUCKET", "env-bucket")
	t.Setenv("S3VAULT_S3_SECRET_KEY", "env-secret")
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
	assert.Equal(t, "env-bucket", cfg.S3.Bucket)
	assert.Equal(t, "env-secret", cfg.S3.SecretKey)
	assert.True(t, cfg.Server.S3BucketAsPrefix)
	assert.Equal(t, BackendLocal, cfg.Backend.Type)
	assert.Equal(t, "/srv/s3vault/objects", cfg.Backend.Local.Dir)
}

func TestEnvIgnoredWithoutBindEnv(t *testing.T) {
	t.Setenv("S3VAULT_S3_BUCKET", "env-bucket")

	v := viper.New()
	SetDefaults(v)
	v.SetEnvPrefix("S3VAULT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Empty(t, cfg.S3.Bucket, "AutomaticEnv alone must not populate Unmarshal for unbound keys")
}

// configFieldKeys walks Config and returns every "a.b" mapstructure path.
func configFieldKeys(t *testing.T) map[string]struct{} {
	t.Helper()

	keys := map[string]struct{}{}

	var walk func(prefix string, typ reflect.Type)

	walk = func(prefix string, typ reflect.Type) {
		for f := range typ.Fields() {
			tag := f.Tag.Get("mapstructure")
			if tag == "" || tag == "-" {
				continue
			}

			path := tag
			if prefix != "" {
				path = prefix + "." + tag
			}

			if f.Type.Kind() == reflect.Struct && f.Type.PkgPath() != "" {
				walk(path, f.Type)

				continue
			}

			keys[path] = struct{}{}
		}
	}

	walk("", reflect.TypeFor[Config]())

	return keys
}

// TestEnvKeysMatchConfigFields keeps envKeys honest in both directions.
// A key listed in envKeys but absent from Config used to look wired while
// nothing read it: that is exactly how the dead `s3.tls` boolean survived.
func TestEnvKeysMatchConfigFields(t *testing.T) {
	t.Parallel()

	fields := configFieldKeys(t)
	bound := make(map[string]struct{}, len(envKeys))

	for _, k := range envKeys {
		_, dup := bound[k]
		require.False(t, dup, "duplicate key in envKeys: %s", k)

		bound[k] = struct{}{}

		assert.Contains(t, fields, k, "envKeys lists a key with no Config field")
	}

	for k := range fields {
		assert.Contains(t, bound, k, "Config field is not bound for S3VAULT_* environment lookup")
	}
}

// TestCommandArgvFromEnv pins the env override for the command-mode argv
// slices: .env.example advertises these keys, so they must actually bind.
func TestCommandArgvFromEnv(t *testing.T) {
	t.Setenv("S3VAULT_ENCRYPTION_COMMAND_ENCRYPT", "cryptcp,-encrypt,--thumbprint,AA")
	t.Setenv("S3VAULT_ENCRYPTION_COMMAND_DECRYPT", "cryptcp,-decrypt,--thumbprint,AA")

	v := viper.New()
	SetDefaults(v)
	v.SetEnvPrefix("S3VAULT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()
	require.NoError(t, BindEnv(v))

	cfg, err := Load(v)
	require.NoError(t, err)
	assert.Equal(t, []string{"cryptcp", "-encrypt", "--thumbprint", "AA"}, cfg.Encryption.Command.Encrypt)
	assert.Equal(t, []string{"cryptcp", "-decrypt", "--thumbprint", "AA"}, cfg.Encryption.Command.Decrypt)
}
