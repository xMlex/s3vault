package config_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/config"
)

// The request spool defaults beside the cache, never inside it: `cache clear`
// deletes every child of cache.dir, and the spool must work with the cache off.
func TestSpoolDirDefault(t *testing.T) {
	t.Parallel()

	v := viper.New()
	config.SetDefaults(v)
	v.Set("cache.dir", "/srv/s3vault/cache")

	cfg, err := config.Load(v)
	require.NoError(t, err)

	assert.Equal(t, "/srv/s3vault/cache-spool", cfg.Server.SpoolDir)
	assert.NotContains(t, cfg.Server.SpoolDir, cfg.Cache.Dir+string(filepath.Separator))
	assert.Equal(t, time.Hour, cfg.Server.SpoolTTL)
	assert.Equal(t, config.MaxMultipartPartSize, cfg.Server.PutMaxBytes)
}

func TestSpoolDirMustNotOverlapOtherPlaintextTrees(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	cache := filepath.Join(base, "cache")
	objects := filepath.Join(base, "objects")
	multipart := filepath.Join(base, "multipart")

	tests := []struct {
		name    string
		spool   string
		wantErr string
	}{
		{name: "own directory", spool: filepath.Join(base, "spool")},
		{name: "equals cache.dir", spool: cache, wantErr: "cache.dir"},
		{name: "inside cache.dir", spool: filepath.Join(cache, "spool"), wantErr: "cache.dir"},
		{name: "equals multipart dir", spool: multipart, wantErr: "server.multipart_dir"},
		{name: "equals local objects", spool: objects, wantErr: "backend.local.dir"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := viper.New()
			config.SetDefaults(v)
			v.Set("backend.type", config.BackendLocal)
			v.Set("backend.local.dir", objects)
			v.Set("cache.dir", cache)
			v.Set("server.multipart_dir", multipart)
			v.Set("server.spool_dir", tt.spool)

			_, err := config.Load(v)
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), "server.spool_dir")
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestNativeChunkSizeBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		chunk   int
		wantErr bool
	}{
		{name: "default", chunk: 0},
		{name: "minimum", chunk: config.MinNativeChunkSize},
		{name: "maximum", chunk: config.MaxNativeChunkSize},
		{name: "too small", chunk: config.MinNativeChunkSize - 1, wantErr: true},
		{name: "too large", chunk: config.MaxNativeChunkSize + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := viper.New()
			config.SetDefaults(v)
			v.Set("encryption.mode", "native")
			v.Set("encryption.native.key_file", "/tmp/kek")

			if tt.chunk != 0 {
				v.Set("encryption.native.chunk_size", tt.chunk)
			}

			cfg, err := config.Load(v)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "chunk_size")

				return
			}

			require.NoError(t, err)

			if tt.chunk == 0 {
				assert.Equal(t, config.DefaultNativeChunkSize, cfg.Encryption.Native.ChunkSize)
			} else {
				assert.Equal(t, tt.chunk, cfg.Encryption.Native.ChunkSize)
			}
		})
	}
}
