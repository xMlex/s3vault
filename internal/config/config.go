package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/period"
)

// Config is the resolved application configuration.
type Config struct {
	Log        LogConfig        `mapstructure:"log"`
	S3         S3Config         `mapstructure:"s3"`
	Encryption EncryptionConfig `mapstructure:"encryption"`
	Cache      CacheConfig      `mapstructure:"cache"`
	Server     ServerConfig     `mapstructure:"server"`
	Remote     RemoteConfig     `mapstructure:"remote"`
	Archive    ArchiveConfig    `mapstructure:"archive"`
}

type LogConfig struct {
	Level string `mapstructure:"level"`
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
	TLS                bool   `mapstructure:"tls"`
	AllowSecretsInFile bool   `mapstructure:"allow_secrets_in_config"`
}

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
	Dir string        `mapstructure:"dir"`
	TTL time.Duration `mapstructure:"ttl"`
	// SoftTTL is how long Materialize may serve a cache hit without S3 HEAD.
	// After SoftTTL, the stale entry is served while revalidation runs in the
	// background (stale-while-revalidate). Zero forces a synchronous HEAD each time.
	SoftTTL time.Duration `mapstructure:"soft_ttl"`
	// SweepInterval is how often the server drops hard-TTL expired entries.
	// Zero disables the background sweeper (lazy delete on Get still applies).
	SweepInterval time.Duration `mapstructure:"sweep_interval"`
	MaxBytes      int64         `mapstructure:"max_bytes"`
}

type ServerConfig struct {
	Listen        string `mapstructure:"listen"`
	MetricsListen string `mapstructure:"metrics_listen"`
	Token         string `mapstructure:"token"`
}

// RemoteConfig is used by archive/upload clients that send plaintext to a
// remote s3vault server (CryptoPro/S3 stay on that host). Auth reuses server.token.
type RemoteConfig struct {
	URL          string `mapstructure:"url"`            // e.g. https://s3vault.example:8080
	RateLimitBPS int64  `mapstructure:"rate_limit_bps"` // max upload bytes/sec across workers; 0 = unlimited
}

type ArchiveConfig struct {
	OlderThan         string `mapstructure:"older_than"`
	Workers           int    `mapstructure:"workers"`
	OnChange          string `mapstructure:"on_change"`
	FollowSymlinks    bool   `mapstructure:"follow_symlinks"`
	FailFast          bool   `mapstructure:"fail_fast"`
	DeleteAfterUpload bool   `mapstructure:"delete_after_upload"`
	DeleteIfExists    bool   `mapstructure:"delete_if_exists"`
}

// SetDefaults registers viper defaults (lowest precedence).
func SetDefaults(v *viper.Viper) {
	v.SetDefault("log.level", "info")
	v.SetDefault("s3.region", "us-east-1")
	v.SetDefault("s3.tls", true)
	v.SetDefault("encryption.mode", "none")
	v.SetDefault("encryption.native.wrap", "rsa-oaep")
	v.SetDefault("encryption.native.chunk_size", 65536)
	v.SetDefault("encryption.command.provider", "cryptopro")
	v.SetDefault("encryption.command.timeout", "30m")
	v.SetDefault("cache.ttl", "168h")
	v.SetDefault("cache.soft_ttl", "20s")
	v.SetDefault("cache.sweep_interval", "15m")
	v.SetDefault("cache.max_bytes", int64(10*1024*1024*1024))
	v.SetDefault("server.listen", "127.0.0.1:8080")
	v.SetDefault("server.metrics_listen", "127.0.0.1:9090")
	v.SetDefault("archive.older_than", "7d")
	v.SetDefault("archive.workers", 4)
	v.SetDefault("archive.on_change", "overwrite")
}

// envKeys are all Config fields that may be set via S3VAULT_* environment
// variables. Viper's AutomaticEnv alone does not apply env values during
// Unmarshal for keys that have no default and are absent from the YAML file;
// BindEnv registers those keys so Unmarshal sees them.
var envKeys = []string{
	"log.level",
	"s3.endpoint",
	"s3.region",
	"s3.bucket",
	"s3.prefix",
	"s3.access_key",
	"s3.secret_key",
	"s3.session_token",
	"s3.path_style",
	"s3.tls",
	"s3.allow_secrets_in_config",
	"encryption.mode",
	"encryption.native.wrap",
	"encryption.native.public_key_path",
	"encryption.native.private_key_path",
	"encryption.native.key_file",
	"encryption.native.chunk_size",
	"encryption.command.provider",
	"encryption.command.thumbprint",
	"encryption.command.timeout",
	"cache.dir",
	"cache.ttl",
	"cache.soft_ttl",
	"cache.sweep_interval",
	"cache.max_bytes",
	"server.listen",
	"server.metrics_listen",
	"server.token",
	"remote.url",
	"remote.rate_limit_bps",
	"archive.older_than",
	"archive.workers",
	"archive.on_change",
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
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := cfg.Normalize(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Normalize fills derived fields and checks invariants.
func (c *Config) Normalize() error {
	c.Log.Level = strings.ToLower(strings.TrimSpace(c.Log.Level))
	c.Encryption.Mode = strings.ToLower(strings.TrimSpace(c.Encryption.Mode))
	c.Archive.OnChange = strings.ToLower(strings.TrimSpace(c.Archive.OnChange))
	c.Remote.URL = strings.TrimRight(strings.TrimSpace(c.Remote.URL), "/")
	if c.Remote.RateLimitBPS < 0 {
		return fmt.Errorf("remote.rate_limit_bps: must be >= 0")
	}
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
	if _, err := period.Parse(c.Archive.OlderThan); err != nil {
		return fmt.Errorf("archive.older_than: %w", err)
	}
	if _, ok := identity.ParseOnChange(c.Archive.OnChange); !ok {
		return fmt.Errorf("archive.on_change: unknown value %q", c.Archive.OnChange)
	}
	switch c.Encryption.Mode {
	case "none", "native", "command":
	default:
		return fmt.Errorf("encryption.mode: unknown value %q", c.Encryption.Mode)
	}
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
	return v.InConfig("s3.secret_key") || v.InConfig("server.token")
}

// WarnSecrets is the user-facing warning for secrets in a config file.
func WarnSecrets() error {
	return errors.New("secret values found in config file; prefer environment variables or set s3.allow_secrets_in_config: true")
}
