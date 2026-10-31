//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	"github.com/xMlex/s3vault/internal/adapter/s3auth/secretbox"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/port"
)

func testIdentity(t *testing.T) (*Identity, []byte) {
	t.Helper()

	dsn := os.Getenv("S3VAULT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("S3VAULT_TEST_POSTGRES_DSN is not set")
	}

	key, err := secretbox.ParseKey(mustMasterKey(t))
	require.NoError(t, err)

	profiles, err := encrypt.NewResolver(config.EncryptionConfig{Mode: "none"})
	require.NoError(t, err)

	// Clear a previous run before Open validates existing rows. The tables may
	// not exist yet, in which case Open's migration creates them.
	if clean, cleanErr := pgxpool.New(t.Context(), dsn); cleanErr == nil {
		_, _ = clean.Exec(t.Context(),
			"TRUNCATE s3vault_users, s3vault_targets, s3vault_encryption_profiles RESTART IDENTITY")
		clean.Close()
	}

	id, err := Open(t.Context(), Config{
		DSN:          dsn,
		MaxConns:     2,
		QueryTimeout: 2 * time.Second,
		MasterKey:    key,
		Bucket:       "s3vault",
		ValidateEncryption: func(raw json.RawMessage) error {
			_, err := profiles.ResolveRaw(raw)

			return err
		},
	})
	require.NoError(t, err)
	t.Cleanup(id.Close)

	truncateAll(t, id)
	t.Cleanup(func() { truncateAll(t, id) })

	return id, key
}

func truncateAll(t *testing.T, id *Identity) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := id.pool.Exec(ctx,
		"TRUNCATE s3vault_users, s3vault_targets, s3vault_encryption_profiles RESTART IDENTITY")
	require.NoError(t, err)
}

const testMasterKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func mustMasterKey(t *testing.T) string {
	t.Helper()

	return testMasterKey
}

func TestIntegrationUsers(t *testing.T) {
	id, _ := testIdentity(t)
	ctx := t.Context()

	profile, err := id.AddEncryptionProfile(ctx, "shared-none", json.RawMessage(`{"mode":"none"}`))
	require.NoError(t, err)
	assert.NotEmpty(t, profile.UID)

	u, secret, err := id.AddUser(ctx, AddParams{
		Name: "alice", Prefix: "tenant-a", EncryptionProfileName: profile.Name,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, u.AccessKeyID)
	assert.NotEmpty(t, secret)
	assert.Equal(t, "tenant-a", u.Prefix)
	assert.True(t, u.Enabled)
	require.NotNil(t, u.EncryptionProfile)
	assert.Equal(t, profile.Name, u.EncryptionProfile.Name)
	assert.Nil(t, u.Target)

	// The stored secret is ciphertext, not the value handed to the operator.
	var stored []byte
	require.NoError(t, id.pool.QueryRow(ctx,
		"SELECT secret_key_ciphertext FROM s3vault_users WHERE access_key_id = $1", u.AccessKeyID,
	).Scan(&stored))
	assert.NotContains(t, string(stored), secret)

	p, ok, err := id.Lookup(ctx, u.AccessKeyID)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, secret, p.SecretKey)
	assert.Equal(t, u.ID, p.User.ID)
	assert.Equal(t, "tenant-a", p.User.Prefix)
	assert.JSONEq(t, `{"mode":"none"}`, string(p.User.Encryption))

	require.NoError(t, id.Allow(ctx, p, port.S3OpGet, "s3vault", "dir/file"))
	assert.ErrorIs(t, id.Allow(ctx, p, port.S3OpGet, "other", "dir/file"), port.ErrAccessDenied)
	assert.ErrorIs(t, id.Allow(ctx, p, port.S3OpGet, "s3vault", "../secret"), port.ErrAccessDenied)

	newSecret, err := id.RotateSecret(ctx, u.AccessKeyID)
	require.NoError(t, err)
	require.NotEqual(t, secret, newSecret)

	_, ok, err = id.Lookup(ctx, u.AccessKeyID)
	require.NoError(t, err)
	require.True(t, ok)

	require.NoError(t, id.SetEnabled(ctx, u.AccessKeyID, false))
	_, _, err = id.Lookup(ctx, u.AccessKeyID)
	assert.ErrorIs(t, err, port.ErrAccessDenied)

	require.NoError(t, id.SetEnabled(ctx, u.AccessKeyID, true))
	_, ok, err = id.Lookup(ctx, u.AccessKeyID)
	require.NoError(t, err)
	assert.True(t, ok)

	_, _, err = id.AddUser(ctx, AddParams{Name: "bob", Prefix: "tenant-a/sub"})
	assert.ErrorContains(t, err, "overlaps")

	// A second user with the same profile is the supported way to share it.
	bob, _, err := id.AddUser(ctx, AddParams{
		Name: "bob", Prefix: "tenant-b", EncryptionProfileName: profile.Name,
	})
	require.NoError(t, err)
	require.NotNil(t, bob.EncryptionProfile)
	assert.Equal(t, profile.UID, bob.EncryptionProfile.UID)

	_, _, err = id.AddUser(ctx, AddParams{
		Name: "ghost", Prefix: "tenant-ghost", EncryptionProfileName: "missing",
	})
	assert.ErrorIs(t, err, ErrEncryptionProfileNotFound)

	updated, err := id.UpdateUser(ctx, u.AccessKeyID, UpdateParams{Prefix: ptr("tenant-c")})
	require.NoError(t, err)
	assert.Equal(t, "tenant-c", updated.Prefix)
	require.NotNil(t, updated.EncryptionProfile)
	assert.Equal(t, profile.Name, updated.EncryptionProfile.Name)

	empty, _, err := id.AddUser(ctx, AddParams{Name: "global", Prefix: "tenant-global"})
	require.NoError(t, err)
	assert.Nil(t, empty.EncryptionProfile, "no profile means the gateway profile")

	users, err := id.ListUsers(ctx)
	require.NoError(t, err)
	require.Len(t, users, 3)

	// Renaming a shared profile is visible to every assigned user.
	renamed, err := id.UpdateEncryptionProfile(ctx, profile.Name, json.RawMessage(`{"mode":"none"}`), "renamed-none")
	require.NoError(t, err)
	assert.Equal(t, "renamed-none", renamed.Name)
	assert.Equal(t, int64(2), renamed.Users)

	p, ok, err = id.Lookup(ctx, u.AccessKeyID)
	require.NoError(t, err)
	require.True(t, ok)
	assert.JSONEq(t, `{"mode":"none"}`, string(p.User.Encryption))

	// It cannot be removed while assigned.
	assert.ErrorIs(t, id.RemoveEncryptionProfile(ctx, "renamed-none"), ErrEncryptionProfileInUse)

	_, err = id.UpdateUser(ctx, u.AccessKeyID, UpdateParams{ClearEncryption: true})
	require.NoError(t, err)
	_, err = id.UpdateUser(ctx, bob.AccessKeyID, UpdateParams{ClearEncryption: true})
	require.NoError(t, err)
	require.NoError(t, id.RemoveEncryptionProfile(ctx, "renamed-none"))
}

func TestIntegrationTarget(t *testing.T) {
	id, key := testIdentity(t)
	ctx := t.Context()

	target := &port.S3Target{
		Endpoint:     "https://s3.example.com",
		Region:       "eu-central-1",
		Bucket:       "archive",
		Prefix:       "vault",
		PathStyle:    true,
		AccessKey:    "AKIATARGET",
		SecretKey:    "target-secret",
		SessionToken: "target-session",
		SSEKMS:       &port.SSEKMS{KeyID: "alias/vault", Context: map[string]string{"tenant": "alice"}, BucketKey: true},
		StorageClass: "GLACIER_IR",
	}

	info, err := id.AddTarget(ctx, "archive", *target)
	require.NoError(t, err)
	assert.Len(t, info.UID, 32)
	assert.Zero(t, info.Users)
	assert.Equal(t, "archive", info.Name)

	alice, _, err := id.AddUser(ctx, AddParams{
		Name: "alice", Prefix: "tenant-a", TargetName: info.Name,
	})
	require.NoError(t, err)
	bob, _, err := id.AddUser(ctx, AddParams{
		Name: "bob", Prefix: "tenant-b", TargetName: info.Name,
	})
	require.NoError(t, err)

	// One target row, two users: the target is shared, not copied.
	var targetRows int
	require.NoError(t, id.pool.QueryRow(ctx, `SELECT count(*) FROM s3vault_targets`).Scan(&targetRows))
	assert.Equal(t, 1, targetRows)

	list, err := id.ListTargets(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, int64(2), list[0].Users)
	assert.Equal(t, "GLACIER_IR", list[0].StorageClass)
	require.NotNil(t, list[0].SSEKMS)

	for _, keyID := range []string{alice.AccessKeyID, bob.AccessKeyID} {
		p, ok, err := id.Lookup(ctx, keyID)
		require.NoError(t, err)
		require.True(t, ok)
		require.NotNil(t, p.User.Target)
		assert.Equal(t, *target, *p.User.Target)
	}

	// Renaming and replacing the target keeps the same uid and re-seals under the
	// target AAD; both users see the new config on the next Lookup.
	next := *target
	next.Bucket = "archive-two"
	next.SecretKey = "new-target-secret"
	next.SessionToken = ""

	renamed, err := id.UpdateTarget(ctx, "archive", next, "archive-two")
	require.NoError(t, err)
	assert.Equal(t, "archive-two", renamed.Name)
	assert.Equal(t, info.UID, renamed.UID)
	assert.Equal(t, int64(2), renamed.Users)

	p, ok, err := id.Lookup(ctx, alice.AccessKeyID)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "archive-two", p.User.Target.Bucket)
	assert.Equal(t, "new-target-secret", p.User.Target.SecretKey)
	assert.Empty(t, p.User.Target.SessionToken)

	assert.ErrorIs(t, id.RemoveTarget(ctx, "archive-two"), ErrTargetInUse)

	_, err = id.UpdateUser(ctx, alice.AccessKeyID, UpdateParams{ClearTarget: true})
	require.NoError(t, err)
	assert.ErrorIs(t, id.RemoveTarget(ctx, "archive-two"), ErrTargetInUse)

	_, err = id.UpdateUser(ctx, bob.AccessKeyID, UpdateParams{ClearTarget: true})
	require.NoError(t, err)
	require.NoError(t, id.RemoveTarget(ctx, "archive-two"))

	// A ciphertext moved between targets does not decrypt: the AAD is the target
	// uid, not the frontend access key.
	one, err := id.AddTarget(ctx, "one", port.S3Target{
		Bucket: "b1", AccessKey: "AKIA1", SecretKey: "secret-one",
	})
	require.NoError(t, err)
	two, err := id.AddTarget(ctx, "two", port.S3Target{
		Bucket: "b2", AccessKey: "AKIA2", SecretKey: "secret-two",
	})
	require.NoError(t, err)

	_, err = id.pool.Exec(ctx,
		`UPDATE s3vault_targets
		    SET secret_nonce = (SELECT secret_nonce FROM s3vault_targets WHERE uid = $1),
		        secret_ciphertext = (SELECT secret_ciphertext FROM s3vault_targets WHERE uid = $1)
		  WHERE uid = $2`, one.UID, two.UID)
	require.NoError(t, err)

	_, err = Open(ctx, Config{
		DSN:          os.Getenv("S3VAULT_TEST_POSTGRES_DSN"),
		MaxConns:     1,
		QueryTimeout: 2 * time.Second,
		MasterKey:    key,
		Bucket:       "s3vault",
	})
	require.Error(t, err)

	// The corrupt row is cleaned up by the next testIdentity; do not leave it
	// behind for the current test's cleanup, which only truncates.
}

func TestIntegrationStartupValidation(t *testing.T) {
	id, key := testIdentity(t)
	ctx := t.Context()

	_, _, err := id.AddUser(ctx, AddParams{Name: "alice", Prefix: "a"})
	require.NoError(t, err)

	nonce, ciphertext, err := secretbox.Seal(key, []byte("secret"), "S3VOVERLAP")
	require.NoError(t, err)
	_, err = id.pool.Exec(ctx,
		`INSERT INTO s3vault_users (name, access_key_id, secret_key_nonce, secret_key_ciphertext, prefix)
		 VALUES ('bob', 'S3VOVERLAP', $1, $2, 'a/b')`, nonce, ciphertext)
	require.NoError(t, err)

	_, err = Open(ctx, Config{
		DSN:          os.Getenv("S3VAULT_TEST_POSTGRES_DSN"),
		MaxConns:     1,
		QueryTimeout: 2 * time.Second,
		MasterKey:    key,
		Bucket:       "s3vault",
	})
	require.ErrorContains(t, err, "overlapping")

	truncateAll(t, id)

	_, _, err = id.AddUser(ctx, AddParams{Name: "alice", Prefix: "a"})
	require.NoError(t, err)

	wrong := append([]byte(nil), key...)
	wrong[0] ^= 0xff
	_, err = Open(ctx, Config{
		DSN:          os.Getenv("S3VAULT_TEST_POSTGRES_DSN"),
		MaxConns:     1,
		QueryTimeout: 2 * time.Second,
		MasterKey:    wrong,
		Bucket:       "s3vault",
	})
	require.ErrorContains(t, err, "authentication failed")

	// A corrupt shared profile fails startup even before a user references it.
	_, err = id.pool.Exec(ctx,
		`INSERT INTO s3vault_encryption_profiles (uid, name, config)
		 VALUES ('0123456789abcdef0123456789abcdef', 'broken', '{"mode":"bogus"}')`)
	require.NoError(t, err)

	_, err = Open(ctx, Config{
		DSN:          os.Getenv("S3VAULT_TEST_POSTGRES_DSN"),
		MaxConns:     1,
		QueryTimeout: 2 * time.Second,
		MasterKey:    key,
		Bucket:       "s3vault",
		ValidateEncryption: func(raw json.RawMessage) error {
			resolver, err := encrypt.NewResolver(config.EncryptionConfig{Mode: "none"})
			if err != nil {
				return err
			}

			_, err = resolver.ResolveRaw(raw)

			return err
		},
	})
	require.Error(t, err)

	// Admin commands open the identity without validating existing rows, so the
	// corrupt profile above does not lock the operator out of removing it.
	admin, err := Open(ctx, Config{
		DSN:            os.Getenv("S3VAULT_TEST_POSTGRES_DSN"),
		MaxConns:       1,
		QueryTimeout:   2 * time.Second,
		MasterKey:      key,
		Bucket:         "s3vault",
		SkipValidation: true,
	})
	require.NoError(t, err)
	admin.Close()

	// The final schema has no legacy per-user encryption/target columns.
	var legacy bool
	require.NoError(t, id.pool.QueryRow(ctx,
		`SELECT EXISTS (
		    SELECT 1 FROM information_schema.columns
		     WHERE table_schema = current_schema()
		       AND table_name = 's3vault_users'
		       AND column_name = 'encryption'
		 )`).Scan(&legacy))
	assert.False(t, legacy)
}

func TestIntegrationDisabledLookup(t *testing.T) {
	id, _ := testIdentity(t)
	ctx := t.Context()

	u, _, err := id.AddUser(ctx, AddParams{Name: "alice", Prefix: "tenant-a"})
	require.NoError(t, err)
	require.NoError(t, id.SetEnabled(ctx, u.AccessKeyID, false))

	_, ok, err := id.Lookup(ctx, u.AccessKeyID)
	assert.False(t, ok)
	assert.True(t, errors.Is(err, port.ErrAccessDenied))
}

func ptr[T any](v T) *T { return &v }
