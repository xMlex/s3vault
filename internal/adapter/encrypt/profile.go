package encrypt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/port"
)

const defaultCommandTimeout = 30 * time.Minute

// Profile is a resolved encryption policy: the writer/primary encryptor, the
// optional global fallback for reads of objects written under another
// algorithm, and a fingerprint that isolates plaintext cache entries.
type Profile struct {
	Primary     port.Encryptor
	Fallback    port.Encryptor
	Fingerprint string
}

// Resolver builds profiles from the user's JSONB value. It holds the gateway's
// global encryption config, which is both the default profile and the fallback.
//
// A non-global profile is cached by its key material, not by the user: the cache
// key includes Fingerprint(cfg), which hashes the actual PEM / KEK file contents
// and the KEK environment value. A rotated key or an edited config therefore
// misses on the next request and is rebuilt, while an unchanged profile reuses
// the parsed RSA key instead of re-reading and re-parsing the PEM per request.
type Resolver struct {
	defaultEnc port.Encryptor
	defaultFP  string

	mu       sync.Mutex
	profiles map[string]Profile
}

// maxCachedProfiles bounds the profile cache. The number of distinct profile
// configurations is operator-driven and small; on overflow the whole cache is
// dropped, which costs one rebuild each on the next request.
const maxCachedProfiles = 64

// NewResolver validates the global config and builds the default profile.
func NewResolver(cfg config.EncryptionConfig) (*Resolver, error) {
	enc, err := New(cfg)
	if err != nil {
		return nil, fmt.Errorf("default encryption: %w", err)
	}

	return &Resolver{defaultEnc: enc, defaultFP: Fingerprint(cfg), profiles: map[string]Profile{}}, nil
}

// Default returns the global profile. The caller may keep it; it is immutable.
func (r *Resolver) Default() Profile {
	return Profile{Primary: r.defaultEnc, Fingerprint: r.defaultFP}
}

// ResolveRaw parses a user's encryption JSON. Nil, null, {}, and an empty mode
// all mean "use the gateway default". A non-empty profile is complete: there is
// no field-by-field merge with the global config.
func (r *Resolver) ResolveRaw(raw json.RawMessage) (Profile, error) {
	return r.Resolve(raw, nil)
}

// Resolve is ResolveRaw plus a sealed KEK injected by a database-backed profile.
// The key is used only by native keyfile wrap and overrides key_file/key_env.
func (r *Resolver) Resolve(raw json.RawMessage, kek []byte) (Profile, error) {
	if isGlobalProfile(raw) {
		return r.Default(), nil
	}

	p, err := decodeProfile(raw)
	if err != nil {
		return Profile{}, err
	}

	if strings.TrimSpace(p.Mode) == "" {
		return r.Default(), nil
	}

	cfg, err := profileConfig(p, kek)
	if err != nil {
		return Profile{}, err
	}

	// Fingerprint hashes the key material itself (PEM/KEK file bytes, env value),
	// so it is both the cache-id input and the invalidation signal. It is
	// computed once here and reused below.
	fp := Fingerprint(cfg)
	key := profileCacheKey(cfg, fp)

	if cached, ok := r.cachedProfile(key); ok {
		return cached, nil
	}

	enc, err := New(cfg)
	if err != nil {
		return Profile{}, fmt.Errorf("user encryption: %w", err)
	}

	profile := Profile{Primary: enc, Fingerprint: fp}

	if Name(r.defaultEnc) != Name(enc) {
		profile.Fallback = r.defaultEnc
		profile.Fingerprint = combineFingerprint(fp, r.defaultFP)
	}

	r.rememberProfile(key, profile)

	return profile, nil
}

// profileCacheKey combines the key-material fingerprint with the settings that
// Fingerprint does not cover (chunk size, encrypt argv, command timeout). Two
// profiles that differ in any of them must not share an encryptor.
func profileCacheKey(cfg config.EncryptionConfig, fp string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, fp)
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, strconv.Itoa(cfg.Native.ChunkSize))
	_, _ = h.Write([]byte{0})

	for _, a := range cfg.Command.Encrypt {
		_, _ = io.WriteString(h, a)
		_, _ = h.Write([]byte{0})
	}

	_, _ = io.WriteString(h, cfg.Command.Timeout.String())

	return hex.EncodeToString(h.Sum(nil))
}

func (r *Resolver) cachedProfile(key string) (Profile, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.profiles[key]

	return p, ok
}

func (r *Resolver) rememberProfile(key string, p Profile) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.profiles == nil {
		r.profiles = make(map[string]Profile)
	}

	if len(r.profiles) >= maxCachedProfiles {
		clear(r.profiles)
	}

	r.profiles[key] = p
}

func isGlobalProfile(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)

	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("{}"))
}

// profileJSON mirrors config.EncryptionConfig, except that command.timeout is a
// Go duration string rather than an integer number of nanoseconds.
type profileJSON struct {
	Mode    string      `json:"mode"`
	Native  nativeJSON  `json:"native"`
	Command commandJSON `json:"command"`
}

type nativeJSON struct {
	Wrap           string `json:"wrap"`
	PublicKeyPath  string `json:"public_key_path"`
	PrivateKeyPath string `json:"private_key_path"`
	KeyFile        string `json:"key_file"`
	KeyEnv         string `json:"key_env"`
	ChunkSize      int    `json:"chunk_size"`
}

type commandJSON struct {
	Encrypt    []string `json:"encrypt"`
	Decrypt    []string `json:"decrypt"`
	Provider   string   `json:"provider"`
	Thumbprint string   `json:"thumbprint"`
	Timeout    string   `json:"timeout"`
}

func decodeProfile(raw json.RawMessage) (profileJSON, error) {
	var p profileJSON

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&p); err != nil {
		return profileJSON{}, fmt.Errorf("parse user encryption: %w", err)
	}

	if err := ensureEOF(dec); err != nil {
		return profileJSON{}, err
	}

	return p, nil
}

func profileConfig(p profileJSON, kek []byte) (config.EncryptionConfig, error) {
	cfg := config.EncryptionConfig{
		Mode: strings.ToLower(strings.TrimSpace(p.Mode)),
		Native: config.NativeEnc{
			Wrap:           p.Native.Wrap,
			PublicKeyPath:  p.Native.PublicKeyPath,
			PrivateKeyPath: p.Native.PrivateKeyPath,
			KeyFile:        p.Native.KeyFile,
			KeyEnv:         strings.TrimSpace(p.Native.KeyEnv),
			Key:            append([]byte(nil), kek...),
			ChunkSize:      p.Native.ChunkSize,
		},
		Command: config.CommandEnc{
			Encrypt:    p.Command.Encrypt,
			Decrypt:    p.Command.Decrypt,
			Provider:   p.Command.Provider,
			Thumbprint: p.Command.Thumbprint,
		},
	}

	switch cfg.Mode {
	case NameNone:
		return cfg, nil
	case NameNative:
		return normalizeNative(cfg)
	case NameCommand:
		return normalizeCommand(cfg, p.Command.Timeout)
	default:
		return config.EncryptionConfig{}, fmt.Errorf("user encryption: unknown mode %q", p.Mode)
	}
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("user encryption: trailing JSON value")
		}

		return fmt.Errorf("parse user encryption: %w", err)
	}

	return nil
}

//nolint:gocyclo // each branch names the exact missing key material and its remedy.
func normalizeNative(cfg config.EncryptionConfig) (config.EncryptionConfig, error) {
	cfg.Native.Wrap = strings.ToLower(strings.TrimSpace(cfg.Native.Wrap))
	if cfg.Native.Wrap == "" {
		cfg.Native.Wrap = WrapRSAOAEP
	}

	if cfg.Native.ChunkSize == 0 {
		cfg.Native.ChunkSize = config.DefaultNativeChunkSize
	}

	if cfg.Native.ChunkSize < config.MinNativeChunkSize || cfg.Native.ChunkSize > config.MaxNativeChunkSize {
		return config.EncryptionConfig{}, fmt.Errorf("user encryption: native.chunk_size must be between %d and %d bytes, got %d",
			config.MinNativeChunkSize, config.MaxNativeChunkSize, cfg.Native.ChunkSize)
	}

	if cfg.Native.PublicKeyPath != "" && !filepath.IsAbs(cfg.Native.PublicKeyPath) {
		return config.EncryptionConfig{}, errors.New("user encryption: native.public_key_path must be absolute")
	}

	if cfg.Native.PrivateKeyPath != "" && !filepath.IsAbs(cfg.Native.PrivateKeyPath) {
		return config.EncryptionConfig{}, errors.New("user encryption: native.private_key_path must be absolute")
	}

	if cfg.Native.KeyFile != "" && !filepath.IsAbs(cfg.Native.KeyFile) {
		return config.EncryptionConfig{}, errors.New("user encryption: native.key_file must be absolute")
	}

	switch cfg.Native.Wrap {
	case WrapRSAOAEP:
		// The gateway both writes and reads with this profile: a public key
		// alone cannot decrypt. A private key derives its public part.
		if cfg.Native.PrivateKeyPath == "" {
			return config.EncryptionConfig{}, errors.New("user encryption: native rsa-oaep requires private_key_path for reads")
		}
	case WrapKeyfile:
		// A KEK may come from key_file, key_env, or a sealed database profile
		// (cfg.Native.Key). Without any of them NewNative falls back to
		// config.DefaultNativeKeyEnv, so absence is not a parse error.
	default:
		return config.EncryptionConfig{}, fmt.Errorf("user encryption: unknown native.wrap %q", cfg.Native.Wrap)
	}

	return cfg, nil
}

func normalizeCommand(cfg config.EncryptionConfig, timeout string) (config.EncryptionConfig, error) {
	if len(cfg.Command.Encrypt) == 0 || len(cfg.Command.Decrypt) == 0 {
		return config.EncryptionConfig{}, errors.New("user encryption: command encrypt and decrypt argv must be set")
	}

	if strings.TrimSpace(cfg.Command.Encrypt[0]) == "" || strings.TrimSpace(cfg.Command.Decrypt[0]) == "" {
		return config.EncryptionConfig{}, errors.New("user encryption: command argv[0] must not be empty")
	}

	cfg.Command.Provider = strings.ToLower(strings.TrimSpace(cfg.Command.Provider))
	if cfg.Command.Provider == "" {
		cfg.Command.Provider = "cryptopro"
	}

	cfg.Command.Thumbprint = config.NormalizeThumbprint(cfg.Command.Thumbprint)
	if cfg.Command.Thumbprint == "" {
		return config.EncryptionConfig{}, errors.New("user encryption: command.thumbprint is required")
	}

	if strings.TrimSpace(timeout) == "" {
		cfg.Command.Timeout = defaultCommandTimeout
	} else {
		d, err := time.ParseDuration(strings.TrimSpace(timeout))
		if err != nil {
			return config.EncryptionConfig{}, fmt.Errorf("user encryption: command.timeout: %w", err)
		}

		if d <= 0 {
			return config.EncryptionConfig{}, fmt.Errorf("user encryption: command.timeout must be positive, got %s", d)
		}

		cfg.Command.Timeout = d
	}

	return cfg, nil
}

func combineFingerprint(primary, fallback string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, primary)
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, fallback)

	return hex.EncodeToString(h.Sum(nil))
}

// Name returns the object-format name of an encryptor ("none", "native",
// "command") or "unknown" for a foreign implementation.
func Name(enc port.Encryptor) string {
	type named interface{ Name() string }
	if n, ok := enc.(named); ok {
		return n.Name()
	}

	return "unknown"
}
