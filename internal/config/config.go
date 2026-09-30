package config

import (
	"errors"
	"fmt"
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
}

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

type ServerConfig struct {
	Listen        string `mapstructure:"listen"`
	MetricsListen string `mapstructure:"metrics_listen"`
	// S3 API (SigV4 plaintext facade). Required: it is the gateway's only data frontend.
	S3Listen         string `mapstructure:"s3_listen"` // empty = multiplex on listen
	S3AccessKey      string `mapstructure:"s3_access_key"`
	S3SecretKey      string `mapstructure:"s3_secret_key"`
	S3Region         string `mapstructure:"s3_region"`
	S3Bucket         string `mapstructure:"s3_bucket"`           // virtual bucket; default = s3.bucket
	S3BucketAsPrefix bool   `mapstructure:"s3_bucket_as_prefix"` // client bucket → key prefix under s3.bucket
	// Multipart spool of the S3 facade. Not cache.dir: the cache is off by
	// default and carries its own invariants, while multipart must work always.
	MultipartDir           string        `mapstructure:"multipart_dir"`
	MultipartTTL           time.Duration `mapstructure:"multipart_ttl"`
	MultipartSweepInterval time.Duration `mapstructure:"multipart_sweep_interval"`
	MultipartMaxSessions   int           `mapstructure:"multipart_max_sessions"`
	MultipartMaxBytes      int64         `mapstructure:"multipart_max_bytes"`
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
	v.SetDefault("s3.region", "us-east-1")
	v.SetDefault("s3.multipart_part_size", DefaultMultipartPartSize)
	v.SetDefault("encryption.mode", "none")
	v.SetDefault("encryption.native.wrap", "rsa-oaep")
	v.SetDefault("encryption.native.chunk_size", 65536)
	v.SetDefault("encryption.command.provider", "cryptopro")
	v.SetDefault("encryption.command.timeout", "30m")
	v.SetDefault("cache.enabled", false)
	v.SetDefault("cache.ttl", "168h")
	v.SetDefault("cache.soft_ttl", "20s")
	v.SetDefault("cache.sweep_interval", "15m")
	v.SetDefault("cache.max_bytes", int64(10*1024*1024*1024))
	v.SetDefault("server.listen", "127.0.0.1:8080")
	v.SetDefault("server.metrics_listen", "127.0.0.1:9090")
	v.SetDefault("server.s3_region", "us-east-1")
	v.SetDefault("server.s3_bucket_as_prefix", false)
	v.SetDefault("server.multipart_ttl", "24h")
	v.SetDefault("server.multipart_sweep_interval", "15m")
	v.SetDefault("server.multipart_max_sessions", 64)
	v.SetDefault("server.multipart_max_bytes", int64(0))
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
	// The multipart spool lives beside the cache directory, not inside it: both
	// hold plaintext on disk, but they are swept by different rules and the
	// cache may be disabled while multipart must keep working.
	if strings.TrimSpace(c.Server.MultipartDir) == "" {
		c.Server.MultipartDir = filepath.Join(c.Cache.Dir, "multipart")
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
	default:
		return fmt.Errorf("backend.type: unknown value %q", c.Backend.Type)
	}
	return nil
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

	return v.InConfig("s3.secret_key") || v.InConfig("server.s3_secret_key")
}

// S3APIEnabled reports whether the SigV4 S3 facade should start.
func (c ServerConfig) S3APIEnabled() bool {
	return c.S3AccessKey != "" && c.S3SecretKey != ""
}

// WarnSecrets is the user-facing warning for secrets in a config file.
func WarnSecrets() error {
	return errors.New("secret values found in config file; prefer environment variables or set s3.allow_secrets_in_config: true")
}
