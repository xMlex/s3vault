package encrypt

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"github.com/xMlex/s3vault/internal/config"
)

// Fingerprint is a stable cache-id input derived from encryption settings and key material.
func Fingerprint(cfg config.EncryptionConfig) string {
	h := sha256.New()
	_, _ = io.WriteString(h, cfg.Mode)
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, cfg.Native.Wrap)
	_, _ = h.Write([]byte{0})
	hashNamed(h, "pub", cfg.Native.PublicKeyPath)
	hashNamed(h, "priv", cfg.Native.PrivateKeyPath)
	hashNamed(h, "kek-file", cfg.Native.KeyFile)
	hashEnv(h, "kek-env", cfg.Native.KeyEnv)

	if len(cfg.Native.Key) > 0 {
		_, _ = h.Write(cfg.Native.Key)
		_, _ = h.Write([]byte{0})
	}
	for _, a := range cfg.Command.Decrypt {
		_, _ = io.WriteString(h, a)
		_, _ = h.Write([]byte{0})
	}
	_, _ = io.WriteString(h, cfg.Command.Provider)
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, cfg.Command.Thumbprint)
	_, _ = h.Write([]byte{0})
	return hex.EncodeToString(h.Sum(nil))
}

func hashNamed(h io.Writer, label, path string) {
	_, _ = io.WriteString(h, label)
	_, _ = io.WriteString(h, path)
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = io.Copy(h, f)
}

// hashEnv includes both the variable name and its current value: a rotated KEK
// must change the cache fingerprint even though the config text did not.
func hashEnv(h io.Writer, label, name string) {
	if name == "" {
		name = config.DefaultNativeKeyEnv
	}

	_, _ = io.WriteString(h, label)
	_, _ = io.WriteString(h, name)
	_, _ = h.Write([]byte{0})

	if value, ok := os.LookupEnv(name); ok {
		_, _ = io.WriteString(h, value)
		_, _ = h.Write([]byte{0})
	}
}
