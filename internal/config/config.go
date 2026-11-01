package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/xMlex/s3vault/internal/period"
)

// Config is the resolved application configuration.
type Config struct {
	Log        LogConfig        `mapstructure:"log"`
	Backend    BackendConfig    `mapstructure:"backend"`
	S3         S3Config         `mapstructure:"s3"`
	Encryption EncryptionConfig `mapstructure:"encryption"`
	Cache      CacheConfig      `mapstructure:"cache"`
	Server     ServerConfig     `mapstructure:"server"`
	Archive    ArchiveConfig    `mapstructure:"archive"`
}

type LogConfig struct {
	Level string `mapstructure:"level"`
}

// Object store backend types for BackendConfig.Type.
const (
	BackendS3    = "s3"
	BackendLocal = "local"
)

// BackendConfig selects which ObjectStore adapter is built.
type BackendConfig struct {
	Type  string      `mapstructure:"type"`
	Local LocalConfig `mapstructure:"local"`
}

// LocalConfig configures the local filesystem object store.
type LocalConfig struct {
	Dir string `mapstructure:"dir"`
	// IndexShards is the number of independent digest index shards kept inside
	// backend.local.dir/.s3vault-index. Zero means the default (8). The index
	// stores sha256 keyed by file version (size, mtime, ctime, inode) for
	// containerless objects so HEAD does not have to rehash every file; each
	// shard is maintained independently.
	IndexShards int `mapstructure:"index_shards"`
}

const (
	// DefaultLocalIndexShards is the default number of digest index shards.
	DefaultLocalIndexShards = 8
	// MaxLocalIndexShards bounds the shard count so an operator cannot create an
	// unbounded number of file descriptors by setting a huge env value.
	MaxLocalIndexShards = 64
)

// LocalIndexDirName is the reserved directory under backend.local.dir that holds
// the digest index. It is never an object key and never listed as one.
const LocalIndexDirName = ".s3vault-index"

// LocalTmpDirName is the reserved directory used for in-flight Put temp files.
const LocalTmpDirName = ".s3vault-tmp"

type S3Config struct {
	Endpoint           string `mapstructure:"endpoint"`
	Region             string `mapstructure:"region"`
	Bucket             string `mapstructure:"bucket"`
	Prefix             string `mapstructure:"prefix"`
	AccessKey          string `mapstructure:"access_key"`
	SecretKey          string `mapstructure:"secret_key"`
	SessionTok         string `mapstructure:"session_token"`
	PathStyle          bool   `mapstructure:"path_style"`
	AllowSecretsInFile bool   `mapstructure:"allow_secrets_in_config"`
	// MultipartPartSize is the size of one multipart part this client writes.
	// It is a writer-side choice, not a negotiated one: it is the size this
	// process sends, and any S3-compatible store — the gateway facade included —
	// accepts whatever legal size it is given. A body of at most one part goes as
	// a single PutObject and never opens a session at all.
	//
	// Zero means "not specified" and becomes DefaultMultipartPartSize; anything
	// else must be legal. The same rule holds in s3store.New, so a fragment built
	// by hand behaves like one that came through Load.
	MultipartPartSize int64 `mapstructure:"multipart_part_size"`
}

// Multipart part size bounds. 5 MiB is the S3 minimum for every part except the
// last, 5 GiB is the S3 maximum for one part.
//
// The default is the minimum, which is what the AWS SDK used before this key
// existed: leaving it there keeps every existing deployment byte-for-byte
// unchanged, and it is also the cheapest profile, since the SDK holds
// Concurrency+1 buffers of exactly this size (~30 MiB at concurrency 5). Raising
// it trades memory for fewer round trips — that is what the key is for, and it is
// a per-deployment decision, not something to bake in. Whichever value is set,
// the SDK raises the part size itself if it would need more than MaxUploadParts
// parts, so a large value is never a hard ceiling.
const (
	MinMultipartPartSize     int64 = 5 << 20
	MaxMultipartPartSize     int64 = 5 << 30
	DefaultMultipartPartSize int64 = MinMultipartPartSize
)

// Native encryption chunk bounds. The chunk size is written into every object
// header, so it is a property of the writer, and the reader must accept whatever
// a writer used — but not without a ceiling: the header is untrusted input, and
// a chunk length of gigabytes would turn a corrupt object into an allocation.
const (
	// MinNativeChunkSize is the smallest useful chunk: one AES-GCM block batch
	// plus the 16-byte tag.
	MinNativeChunkSize = 4 << 10
	// MaxNativeChunkSize bounds a single chunk both when writing and reading.
	MaxNativeChunkSize = 8 << 20
	// DefaultNativeChunkSize matches the historical 64 KiB default.
	DefaultNativeChunkSize = 65536
)

type EncryptionConfig struct {
	Mode    string     `mapstructure:"mode"`
	Native  NativeEnc  `mapstructure:"native"`
	Command CommandEnc `mapstructure:"command"`
}

type NativeEnc struct {
	Wrap           string `mapstructure:"wrap"`
	PublicKeyPath  string `mapstructure:"public_key_path"`
	PrivateKeyPath string `mapstructure:"private_key_path"`
	KeyFile        string `mapstructure:"key_file"`
	ChunkSize      int    `mapstructure:"chunk_size"`
}

type CommandEnc struct {
	Encrypt    []string      `mapstructure:"encrypt"`
	Decrypt    []string      `mapstructure:"decrypt"`
	Provider   string        `mapstructure:"provider"`   // written to S3VCTR01 (default cryptopro)
	Thumbprint string        `mapstructure:"thumbprint"` // CryptoPro SHA-1; written to S3VCTR01
	Timeout    time.Duration `mapstructure:"timeout"`
}

type CacheConfig struct {
	// Enabled turns on the persistent plaintext disk cache for HTTP/S3 Materialize.
	// Default false: each request decrypts to an ephemeral temp file.
	Enabled bool          `mapstructure:"enabled"`
	Dir     string        `mapstructure:"dir"`
	TTL     time.Duration `mapstructure:"ttl"`
	// SoftTTL is how long Materialize may serve a cache hit without S3 HEAD.
	// After SoftTTL, the stale entry is served while revalidation runs in the
	// background (stale-while-revalidate). Zero forces a synchronous HEAD each time.
	// Only applies when Enabled.
	SoftTTL time.Duration `mapstructure:"soft_ttl"`
	// SweepInterval is how often the server drops hard-TTL expired entries.
	// Zero disables the background sweeper (lazy delete on Get still applies).
	SweepInterval time.Duration `mapstructure:"sweep_interval"`
	MaxBytes      int64         `mapstructure:"max_bytes"`
}

// Auth backends for the S3 facade. Exactly one identity source is active per
// process; postgres mode refuses static keys rather than accepting both.
const (
	AuthBackendStatic   = "static"
	AuthBackendPostgres = "postgres"

	DefaultAuthMaxConns       int32 = 8
	DefaultAuthQueryTimeout         = 2 * time.Second
	DefaultAuthTargetPoolMax        = 64
	DefaultAuthTargetPoolIdle       = 15 * time.Minute
)

// ServerAuthConfig selects where frontend S3 credentials and per-user policy
// come from.
type ServerAuthConfig struct {
	Backend      string        `mapstructure:"backend"`
	DSN          string        `mapstructure:"dsn"`
	MaxConns     int32         `mapstructure:"max_conns"`
	QueryTimeout time.Duration `mapstructure:"query_timeout"`
	// TargetPoolMax bounds the per-process pool of ObjectStores for users with
	// their own destination S3. It does not limit users, only simultaneous
	// stores; exceeding it causes LRU rebuilds.
	TargetPoolMax int `mapstructure:"target_pool_max"`
	// TargetPoolIdle evicts a target store that has not been used for this long.
	TargetPoolIdle time.Duration `mapstructure:"target_pool_idle"`
}

type ServerConfig struct {
	Listen        string `mapstructure:"listen"`
	MetricsListen string `mapstructure:"metrics_listen"`
	// S3 API (SigV4 plaintext facade). Required: it is the gateway's only data frontend.
	S3Listen         string           `mapstructure:"s3_listen"` // empty = multiplex on listen
	Auth             ServerAuthConfig `mapstructure:"auth"`
	S3AccessKey      string           `mapstructure:"s3_access_key"`
	S3SecretKey      string           `mapstructure:"s3_secret_key"`
	S3Region         string           `mapstructure:"s3_region"`
	S3Bucket         string           `mapstructure:"s3_bucket"`           // virtual bucket; default = s3.bucket
	S3BucketAsPrefix bool             `mapstructure:"s3_bucket_as_prefix"` // client bucket → key prefix under s3.bucket
	// Multipart spool of the S3 facade. Not cache.dir: the cache is off by
	// default and carries its own invariants, while multipart must work always.
	MultipartDir           string        `mapstructure:"multipart_dir"`
	MultipartTTL           time.Duration `mapstructure:"multipart_ttl"`
	MultipartSweepInterval time.Duration `mapstructure:"multipart_sweep_interval"`
	MultipartMaxSessions   int           `mapstructure:"multipart_max_sessions"`
	MultipartMaxBytes      int64         `mapstructure:"multipart_max_bytes"`
	// SpoolDir holds the facade's request-scoped plaintext: a PutObject body
	// while it is hashed, and a decrypted object served when no cache is
	// configured. It defaults to a sibling of cache.dir, never a child, and is
	// swept by SpoolTTL so a crashed request cannot leave plaintext forever.
	SpoolDir string `mapstructure:"spool_dir"`
	// SpoolTTL is how old an orphaned spool file must be before the sweeper
	// removes it.
	SpoolTTL time.Duration `mapstructure:"spool_ttl"`
	// PutMaxBytes bounds one PutObject/UploadPart request body. The default is
	// the S3 single-PUT ceiling (5 GiB): a larger body cannot succeed anyway, and
	// without a bound one client can fill the spool.
	PutMaxBytes int64 `mapstructure:"put_max_bytes"`
}

type ArchiveConfig struct {
	OlderThan         string `mapstructure:"older_than"`
	Workers           int    `mapstructure:"workers"`
	FollowSymlinks    bool   `mapstructure:"follow_symlinks"`
	FailFast          bool   `mapstructure:"fail_fast"`
	DeleteAfterUpload bool   `mapstructure:"delete_after_upload"`
	DeleteIfExists    bool   `mapstructure:"delete_if_exists"`
}

// SetDefaults registers viper defaults (lowest precedence).
func SetDefaults(v *viper.Viper) {
	v.SetDefault("log.level", "info")
	v.SetDefault("backend.type", BackendS3)
	v.SetDefault("backend.local.index_shards", DefaultLocalIndexShards)
	v.SetDefault("s3.region", "us-east-1")
	v.SetDefault("s3.multipart_part_size", DefaultMultipartPartSize)
	v.SetDefault("encryption.mode", "none")
	v.SetDefault("encryption.native.wrap", "rsa-oaep")
	v.SetDefault("encryption.native.chunk_size", DefaultNativeChunkSize)
	v.SetDefault("encryption.command.provider", "cryptopro")
	v.SetDefault("encryption.command.timeout", "30m")
	v.SetDefault("cache.enabled", false)
	v.SetDefault("cache.ttl", "168h")
	v.SetDefault("cache.soft_ttl", "20s")
	v.SetDefault("cache.sweep_interval", "15m")
	v.SetDefault("cache.max_bytes", int64(10*1024*1024*1024))
	v.SetDefault("server.listen", "127.0.0.1:8080")
	v.SetDefault("server.metrics_listen", "127.0.0.1:9090")
	v.SetDefault("server.auth.backend", AuthBackendStatic)
	v.SetDefault("server.auth.max_conns", DefaultAuthMaxConns)
	v.SetDefault("server.auth.query_timeout", DefaultAuthQueryTimeout)
	v.SetDefault("server.auth.target_pool_max", DefaultAuthTargetPoolMax)
	v.SetDefault("server.auth.target_pool_idle", DefaultAuthTargetPoolIdle)
	v.SetDefault("server.s3_region", "us-east-1")
	v.SetDefault("server.s3_bucket_as_prefix", false)
	v.SetDefault("server.multipart_ttl", "24h")
	v.SetDefault("server.multipart_sweep_interval", "15m")
	v.SetDefault("server.multipart_max_sessions", 64)
	v.SetDefault("server.multipart_max_bytes", int64(0))
	v.SetDefault("server.spool_ttl", "1h")
	v.SetDefault("server.put_max_bytes", MaxMultipartPartSize)
	v.SetDefault("archive.older_than", "7d")
	v.SetDefault("archive.workers", 4)
}

// envKeys are all Config fields that may be set via S3VAULT_* environment
// variables. Viper's AutomaticEnv alone does not apply env values during
// Unmarshal for keys that have no default and are absent from the YAML file;
// BindEnv registers those keys so Unmarshal sees them.
var envKeys = []string{
	"log.level",
	"backend.type",
	"backend.local.dir",
	"backend.local.index_shards",
	"s3.endpoint",
	"s3.region",
	"s3.bucket",
	"s3.prefix",
	"s3.access_key",
	"s3.secret_key",
	"s3.session_token",
	"s3.path_style",
	"s3.allow_secrets_in_config",
	"s3.multipart_part_size",
	"encryption.mode",
	"encryption.native.wrap",
	"encryption.native.public_key_path",
	"encryption.native.private_key_path",
	"encryption.native.key_file",
	"encryption.native.chunk_size",
	"encryption.command.provider",
	"encryption.command.thumbprint",
	"encryption.command.timeout",
	"encryption.command.encrypt",
	"encryption.command.decrypt",
	"cache.enabled",
	"cache.dir",
	"cache.ttl",
	"cache.soft_ttl",
	"cache.sweep_interval",
	"cache.max_bytes",
	"server.listen",
	"server.metrics_listen",
	"server.auth.backend",
	"server.auth.dsn",
	"server.auth.max_conns",
	"server.auth.query_timeout",
	"server.auth.target_pool_max",
	"server.auth.target_pool_idle",
	"server.s3_listen",
	"server.s3_access_key",
	"server.s3_secret_key",
	"server.s3_region",
	"server.s3_bucket",
	"server.s3_bucket_as_prefix",
	"server.multipart_dir",
	"server.multipart_ttl",
	"server.multipart_sweep_interval",
	"server.multipart_max_sessions",
	"server.multipart_max_bytes",
	"server.spool_dir",
	"server.spool_ttl",
	"server.put_max_bytes",
	"archive.older_than",
	"archive.workers",
	"archive.follow_symlinks",
	"archive.fail_fast",
	"archive.delete_after_upload",
	"archive.delete_if_exists",
}

// BindEnv registers every known config key for environment lookup.
// Call after SetEnvPrefix and SetEnvKeyReplacer.
func BindEnv(v *viper.Viper) error {
	for _, key := range envKeys {
		if err := v.BindEnv(key); err != nil {
			return fmt.Errorf("bind env %s: %w", key, err)
		}
	}
	return nil
}

// Load unmarshals viper into Config and validates.
func Load(v *viper.Viper) (Config, error) {
	if err := CheckRemovedKeys(v); err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := cfg.Normalize(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// removedKeys are config keys deleted in the switch to an S3-only gateway. Viper
// silently ignores unknown keys, so a stale key would change behavior without a
// word; refuse to start and name the replacement.
var removedKeys = []struct{ key, hint string }{
	{"remote.url", "remote HTTP ingest was removed; point s3.endpoint and s3.access_key/s3.secret_key at the gateway S3 facade instead"},
	{"remote.rate_limit_bps", "remote HTTP ingest was removed; there is no S3-path bandwidth limiter"},
	{"server.token", "the bearer HTTP /files frontend was removed; authenticate to the gateway with server.s3_access_key/server.s3_secret_key (SigV4)"},
	{"archive.on_change", "the overwrite/skip/fail switch was removed: an upload with differing content is now always written. It was a single global policy read by archive, upload and server alike, which let the gateway answer 200 while discarding the uploaded body (docs/reliability-review.md H2). If you need a per-run policy, add it as an archive-command flag"},
	{"backend.local.layout", "the container/raw switch was removed: encryption.mode alone decides the object shape, on every backend. encryption.mode=none writes the bare payload, native/command write the S3VCTR01 container. Delete the key"},
}

// CheckRemovedKeys returns an error if any key removed from the schema is still
// present in the config file or the environment.
func CheckRemovedKeys(v *viper.Viper) error {
	for _, rk := range removedKeys {
		if v.InConfig(rk.key) || v.IsSet(rk.key) {
			return fmt.Errorf("config key %q was removed: %s", rk.key, rk.hint)
		}
	}

	return nil
}

// Normalize fills derived fields and checks invariants.
func (c *Config) Normalize() error {
	c.Log.Level = strings.ToLower(strings.TrimSpace(c.Log.Level))
	if err := c.normalizeBackend(); err != nil {
		return err
	}

	if err := c.normalizeAuth(); err != nil {
		return err
	}
	c.Encryption.Mode = strings.ToLower(strings.TrimSpace(c.Encryption.Mode))
	if c.Archive.Workers < 1 {
		c.Archive.Workers = 1
	}
	if c.Cache.Dir == "" {
		dir, err := os.UserCacheDir()
		if err != nil {
			return fmt.Errorf("cache dir: %w", err)
		}
		c.Cache.Dir = filepath.Join(dir, "s3vault")
	}
	// Cleaned so the spool sibling below is derived from the real directory: with
	// a trailing separator, filepath.Dir/Base would place it inside the cache.
	c.Cache.Dir = filepath.Clean(c.Cache.Dir)
	// The multipart spool lives beside the cache directory, not inside it: both
	// hold plaintext on disk, but they are swept by different rules, `cache clear`
	// drops every cache shard under cache.dir, and the cache may be disabled while
	// multipart must keep working.
	if strings.TrimSpace(c.Server.MultipartDir) == "" {
		c.Server.MultipartDir = filepath.Join(filepath.Dir(c.Cache.Dir), filepath.Base(c.Cache.Dir)+"-multipart")
	}
	// The request spool has the same relationship to the cache: plaintext on
	// disk, own sweeper, must work while the cache is disabled.
	if strings.TrimSpace(c.Server.SpoolDir) == "" {
		c.Server.SpoolDir = filepath.Join(filepath.Dir(c.Cache.Dir), filepath.Base(c.Cache.Dir)+"-spool")
	}

	c.Server.SpoolDir = filepath.Clean(c.Server.SpoolDir)

	if c.Server.SpoolTTL <= 0 {
		c.Server.SpoolTTL = time.Hour
	}

	if c.Server.PutMaxBytes <= 0 {
		c.Server.PutMaxBytes = MaxMultipartPartSize
	}

	if err := c.checkServerDirs(); err != nil {
		return err
	}
	if _, err := period.Parse(c.Archive.OlderThan); err != nil {
		return fmt.Errorf("archive.older_than: %w", err)
	}
	// Checked here rather than left to the SDK: the SDK's own floor is the same
	// 5 MiB but it reports a bare "part size must be at least N bytes" with no
	// key name, and only at the first upload. Zero is the one value that means
	// "not specified" — it becomes the default rather than an error, exactly as
	// archive.workers below, so that a fragment assembled by hand behaves like one
	// that came through Load.
	if c.S3.MultipartPartSize == 0 {
		c.S3.MultipartPartSize = DefaultMultipartPartSize
	}

	switch {
	case c.S3.MultipartPartSize < MinMultipartPartSize:
		return fmt.Errorf("s3.multipart_part_size: must be %d (default) or at least %d bytes (5 MiB, the S3 minimum for every part but the last), got %d",
			DefaultMultipartPartSize, MinMultipartPartSize, c.S3.MultipartPartSize)
	case c.S3.MultipartPartSize > MaxMultipartPartSize:
		return fmt.Errorf("s3.multipart_part_size: must be at most %d bytes (5 GiB, the S3 maximum for one part), got %d",
			MaxMultipartPartSize, c.S3.MultipartPartSize)
	}
	switch c.Encryption.Mode {
	case "none", "native", "command":
	default:
		return fmt.Errorf("encryption.mode: unknown value %q", c.Encryption.Mode)
	}

	if c.Encryption.Native.ChunkSize == 0 {
		c.Encryption.Native.ChunkSize = DefaultNativeChunkSize
	}
	// Checked here as well as in the reader: the value is written into every
	// object header, and a reader must reject an out-of-range chunk before it
	// allocates a buffer of that size (see encrypt.maxChunkSize).
	if chunk := c.Encryption.Native.ChunkSize; chunk < MinNativeChunkSize || chunk > MaxNativeChunkSize {
		return fmt.Errorf("encryption.native.chunk_size: must be between %d and %d bytes, got %d",
			MinNativeChunkSize, MaxNativeChunkSize, chunk)
	}
	// encryption.mode is the single source of truth for the object shape: mode=none
	// writes the bare payload with no S3VCTR01 container, every other mode wraps.
	// There is no layout switch, so there is no combination to reject here — a
	// containerless object is only ever produced by a process that does not
	// encrypt, and its payload is therefore plaintext by construction.
	c.Encryption.Command.Provider = strings.ToLower(strings.TrimSpace(c.Encryption.Command.Provider))
	if c.Encryption.Mode == "command" && c.Encryption.Command.Provider == "" {
		c.Encryption.Command.Provider = "cryptopro"
	}
	c.Encryption.Command.Thumbprint = NormalizeThumbprint(c.Encryption.Command.Thumbprint)
	if c.Encryption.Mode == "command" && c.Encryption.Command.Thumbprint == "" {
		c.Encryption.Command.Thumbprint = ThumbprintFromArgv(c.Encryption.Command.Encrypt)
	}
	return nil
}

func (c *Config) normalizeAuth() error {
	c.Server.Auth.Backend = strings.ToLower(strings.TrimSpace(c.Server.Auth.Backend))
	if c.Server.Auth.Backend == "" {
		c.Server.Auth.Backend = AuthBackendStatic
	}

	switch c.Server.Auth.Backend {
	case AuthBackendStatic:
		// The static path keeps its historical shape: keys are checked when the
		// S3 handler is built, not here.
	case AuthBackendPostgres:
		c.Server.Auth.DSN = strings.TrimSpace(c.Server.Auth.DSN)
		if c.Server.Auth.DSN == "" {
			return fmt.Errorf("server.auth.dsn: required when server.auth.backend is %q", AuthBackendPostgres)
		}

		if c.Server.S3AccessKey != "" || c.Server.S3SecretKey != "" {
			return fmt.Errorf("server.auth.backend is %q: static server.s3_access_key/server.s3_secret_key must be empty", AuthBackendPostgres)
		}

		if c.Server.S3BucketAsPrefix {
			return fmt.Errorf("server.s3_bucket_as_prefix: not supported with server.auth.backend %q; the user prefix already namespaces every key", AuthBackendPostgres)
		}
	default:
		return fmt.Errorf("server.auth.backend: unknown value %q", c.Server.Auth.Backend)
	}

	if c.Server.Auth.MaxConns < 0 {
		return fmt.Errorf("server.auth.max_conns: must not be negative, got %d", c.Server.Auth.MaxConns)
	}

	if c.Server.Auth.MaxConns == 0 {
		c.Server.Auth.MaxConns = DefaultAuthMaxConns
	}

	if c.Server.Auth.QueryTimeout < 0 {
		return fmt.Errorf("server.auth.query_timeout: must not be negative, got %s", c.Server.Auth.QueryTimeout)
	}

	if c.Server.Auth.QueryTimeout == 0 {
		c.Server.Auth.QueryTimeout = DefaultAuthQueryTimeout
	}

	if c.Server.Auth.TargetPoolMax < 0 {
		return fmt.Errorf("server.auth.target_pool_max: must not be negative, got %d", c.Server.Auth.TargetPoolMax)
	}

	if c.Server.Auth.TargetPoolMax == 0 {
		c.Server.Auth.TargetPoolMax = DefaultAuthTargetPoolMax
	}

	if c.Server.Auth.TargetPoolIdle < 0 {
		return fmt.Errorf("server.auth.target_pool_idle: must not be negative, got %s", c.Server.Auth.TargetPoolIdle)
	}

	if c.Server.Auth.TargetPoolIdle == 0 {
		c.Server.Auth.TargetPoolIdle = DefaultAuthTargetPoolIdle
	}

	return nil
}

func (c *Config) normalizeBackend() error {
	c.Backend.Type = strings.ToLower(strings.TrimSpace(c.Backend.Type))
	if c.Backend.Type == "" {
		c.Backend.Type = BackendS3
	}
	switch c.Backend.Type {
	case BackendS3:
	case BackendLocal:
		dir := strings.TrimSpace(c.Backend.Local.Dir)
		if dir == "" {
			return fmt.Errorf("backend.local.dir: required when backend.type is %q", BackendLocal)
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return fmt.Errorf("backend.local.dir: %w", err)
		}
		c.Backend.Local.Dir = abs
		if c.Backend.Local.IndexShards == 0 {
			c.Backend.Local.IndexShards = DefaultLocalIndexShards
		}
		if c.Backend.Local.IndexShards < 1 || c.Backend.Local.IndexShards > MaxLocalIndexShards {
			return fmt.Errorf("backend.local.index_shards: must be between 1 and %d, got %d",
				MaxLocalIndexShards, c.Backend.Local.IndexShards)
		}
	default:
		return fmt.Errorf("backend.type: unknown value %q", c.Backend.Type)
	}
	return nil
}

// checkServerDirs refuses any pair of plaintext roots that share a tree. The
// multipart spool is wiped at startup, `cache clear` deletes every cache shard,
// and the request spool is swept by its own TTL, so a shared tree turns any of
// them into deletion of somebody else's data: at backend.local.dir it is the
// archived objects, inside cache.dir it is the in-flight upload parts.
func (c *Config) checkServerDirs() error {
	roots := []struct{ key, dir string }{
		{"cache.dir", c.Cache.Dir},
		{"server.multipart_dir", c.Server.MultipartDir},
		{"server.spool_dir", c.Server.SpoolDir},
	}
	if c.Backend.Type == BackendLocal {
		roots = append(roots, struct{ key, dir string }{"backend.local.dir", c.Backend.Local.Dir})
	}

	abs := make([]string, len(roots))
	for i, r := range roots {
		dir, err := filepath.Abs(r.dir)
		if err != nil {
			return fmt.Errorf("%s: %w", r.key, err)
		}

		abs[i] = dir
	}

	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if pathsOverlap(abs[i], abs[j]) {
				return fmt.Errorf(
					"%s %q must not overlap %s %q: "+
						"these trees hold plaintext and are cleaned independently, so they must not share a tree",
					roots[i].key, abs[i], roots[j].key, abs[j],
				)
			}
		}
	}

	return nil
}

// pathsOverlap reports whether one path contains the other (equality included).
// The comparison is lexical: symlinks are not resolved.
func pathsOverlap(a, b string) bool {
	return pathContains(a, b) || pathContains(b, a)
}

// pathContains reports whether child is parent or lies beneath it. Different
// volumes (filepath.Rel erroring on Windows) do not overlap.
func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}

	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// KeyPrefix is the object key prefix for any backend. It lives under s3.prefix
// for config compatibility (the --prefix flag and remote clients use it too).
func (c Config) KeyPrefix() string { return c.S3.Prefix }

// CacheNamespace isolates plaintext cache ids per backend (see cache.ID).
func (c Config) CacheNamespace() string {
	if c.Backend.Type == BackendLocal {
		return "local:" + c.Backend.Local.Dir
	}
	return c.S3.Bucket
}

// NormalizeThumbprint strips spaces and colons from a SHA-1 hex thumbprint.
func NormalizeThumbprint(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == ' ' || r == ':' {
			continue
		}
		if r >= 'A' && r <= 'F' {
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ThumbprintFromArgv returns the last argv element that looks like a SHA-1 thumbprint.
func ThumbprintFromArgv(argv []string) string {
	for i := len(argv) - 1; i >= 0; i-- {
		tp := NormalizeThumbprint(argv[i])
		if isSHA1Hex(tp) {
			return tp
		}
	}
	return ""
}

func isSHA1Hex(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// OlderThanDuration parses archive.older_than.
func (c Config) OlderThanDuration() (time.Duration, error) {
	return period.Parse(c.Archive.OlderThan)
}

// SecretsInPlainConfig reports whether the yaml likely stored a secret.
func SecretsInPlainConfig(v *viper.Viper) bool {
	if v.ConfigFileUsed() == "" {
		return false
	}
	if v.GetBool("s3.allow_secrets_in_config") {
		return false
	}

	if v.InConfig("server.auth.dsn") && dsnCarriesPassword(v.GetString("server.auth.dsn")) {
		return true
	}

	return v.InConfig("s3.secret_key") || v.InConfig("server.s3_secret_key")
}

// dsnCarriesPassword reports whether a PostgreSQL DSN embeds a password. The
// rest of a DSN is configuration; only the password makes it a secret.
func dsnCarriesPassword(dsn string) bool {
	u, err := url.Parse(strings.TrimSpace(dsn))
	if err != nil || u.User == nil {
		return false
	}

	_, hasPassword := u.User.Password()

	return hasPassword
}

// S3APIEnabled reports whether the SigV4 S3 facade should start.
func (c ServerConfig) S3APIEnabled() bool {
	if c.Auth.Backend == AuthBackendPostgres {
		return true
	}

	return c.S3AccessKey != "" && c.S3SecretKey != ""
}

// WarnSecrets is the user-facing warning for secrets in a config file.
func WarnSecrets() error {
	return errors.New("secret values found in config file; prefer environment variables or set s3.allow_secrets_in_config: true")
}
