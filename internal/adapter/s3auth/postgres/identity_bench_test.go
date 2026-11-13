//go:build integration

package postgres

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/adapter/s3auth/secretbox"
	"github.com/xMlex/s3vault/internal/config"
)

// BenchmarkIdentityLookup measures the per-request auth cost of the postgres
// backend: one joined query, AES-GCM opening of the user secret, and (for a user
// that references a profile) the profile KEK. CacheTTL is left at zero here, so
// this is the uncached database path; a cache hit costs ~80 ns
// (BenchmarkPrincipalCacheHit) for the default one-second window.
func BenchmarkIdentityLookup(b *testing.B) {
	dsn := os.Getenv("S3VAULT_TEST_POSTGRES_DSN")
	if dsn == "" {
		b.Skip("S3VAULT_TEST_POSTGRES_DSN is not set")
	}

	key, err := secretbox.ParseKey(testMasterKey)
	if err != nil {
		b.Fatal(err)
	}

	profiles, err := encrypt.NewResolver(config.EncryptionConfig{Mode: "none"})
	if err != nil {
		b.Fatal(err)
	}

	id, err := Open(b.Context(), Config{
		DSN:          dsn,
		MaxConns:     2,
		QueryTimeout: 2 * time.Second,
		MasterKey:    key,
		Bucket:       "s3vault",
		ValidateEncryption: func(raw json.RawMessage, kek []byte) error {
			_, err := profiles.Resolve(raw, kek)

			return err
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(id.Close)

	if _, err := id.pool.Exec(b.Context(),
		"TRUNCATE s3vault_users, s3vault_targets, s3vault_encryption_profiles RESTART IDENTITY"); err != nil {
		b.Fatal(err)
	}

	plain, _, err := id.AddUser(b.Context(), AddParams{Name: "bench-plain", Prefix: "bench-plain"})
	if err != nil {
		b.Fatal(err)
	}

	profile, err := id.AddEncryptionProfile(b.Context(), "bench-none", json.RawMessage(`{"mode":"none"}`), nil)
	if err != nil {
		b.Fatal(err)
	}

	withProfile, _, err := id.AddUser(b.Context(), AddParams{
		Name:                  "bench-profile",
		Prefix:                "bench-profile",
		EncryptionProfileName: profile.Name,
	})
	if err != nil {
		b.Fatal(err)
	}

	cases := []struct {
		name      string
		accessKey string
	}{
		{"secret-only", plain.AccessKeyID},
		{"secret+profile-kek", withProfile.AccessKeyID},
	}

	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				principal, ok, err := id.Lookup(b.Context(), c.accessKey)
				if err != nil {
					b.Fatal(err)
				}

				if !ok {
					b.Fatal("lookup returned no principal")
				}

				_ = principal
			}
		})
	}
}
