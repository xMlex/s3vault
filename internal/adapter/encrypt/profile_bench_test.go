package encrypt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/xMlex/s3vault/internal/config"
)

// BenchmarkResolverResolve measures the per-request cost of resolving a user
// encryption profile after the key-material cache exists: a fingerprint of the
// KEK file plus a map lookup, against ~540 µs for re-parsing an RSA-4096 key
// (BenchmarkNativeNewPerRequest).
func BenchmarkResolverResolve(b *testing.B) {
	keyPath := filepath.Join(b.TempDir(), "kek.bin")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		b.Fatal(err)
	}

	resolver, err := NewResolver(config.EncryptionConfig{Mode: NameNone})
	if err != nil {
		b.Fatal(err)
	}

	raw := json.RawMessage(`{
		"mode": "native",
		"native": {"wrap": "keyfile", "key_file": "` + keyPath + `", "chunk_size": 65536}
	}`)

	if _, err := resolver.ResolveRaw(raw); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := resolver.ResolveRaw(raw); err != nil {
			b.Fatal(err)
		}
	}
}
