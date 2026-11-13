package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/port"
)

var _ port.S3Identity = (*Identity)(nil)

// Lookup resolves a SigV4 access key to its secret and per-user policy. It is
// called on every request. Results are reused for Config.CacheTTL: a disabled
// key, a rotated secret or a changed profile/target is visible within that
// window, and immediately at CacheTTL=0. The database stays authoritative on
// every miss, and a database error is never masked by the cache.
func (i *Identity) Lookup(ctx context.Context, accessKeyID string) (port.Principal, bool, error) {
	if principal, ok := i.cache.get(accessKeyID); ok {
		return principal, true, nil
	}

	ctx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()

	var (
		id         int64
		key        string
		prefix     string
		enabled    bool
		nonce      []byte
		ciphertext []byte

		profileUID    *string
		profileName   *string
		profileConfig []byte
		profileKekN   []byte
		profileKekC   []byte

		targetUID    *string
		targetName   *string
		targetConfig []byte
		tSecretN     []byte
		tSecretC     []byte
		tSessionN    []byte
		tSessionC    []byte
	)

	err := i.pool.QueryRow(ctx,
		`SELECT u.id, u.access_key_id, u.prefix, u.enabled,
		        u.secret_key_nonce, u.secret_key_ciphertext,
		        p.uid, p.name, p.config, p.kek_nonce, p.kek_ciphertext,
		        t.uid, t.name, t.config,
		        t.secret_nonce, t.secret_ciphertext,
		        t.session_nonce, t.session_ciphertext
		   FROM s3vault_users u
		   LEFT JOIN s3vault_encryption_profiles p ON p.uid = u.encryption_profile_uid
		   LEFT JOIN s3vault_targets t ON t.uid = u.s3_target_uid
		  WHERE u.access_key_id = $1`, accessKeyID,
	).Scan(&id, &key, &prefix, &enabled, &nonce, &ciphertext,
		&profileUID, &profileName, &profileConfig, &profileKekN, &profileKekC,
		&targetUID, &targetName, &targetConfig,
		&tSecretN, &tSecretC, &tSessionN, &tSessionC)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.Principal{}, false, nil
	}

	if err != nil {
		return port.Principal{}, false, fmt.Errorf("%w: lookup: %w", port.ErrAuthUnavailable, err)
	}

	if !enabled {
		return port.Principal{}, false, port.ErrAccessDenied
	}

	if !keying.IsCanonicalPrefix(prefix) {
		return port.Principal{}, false, fmt.Errorf("%w: user %d has non-canonical prefix", port.ErrAuthInternal, id)
	}

	secret, err := i.openSecret(key, nonce, ciphertext)
	if err != nil {
		return port.Principal{}, false, fmt.Errorf("%w: decrypt secret for %s: %w", port.ErrAuthInternal, key, err)
	}

	var (
		profile json.RawMessage
		kek     []byte
	)

	if profileUID != nil && len(profileConfig) == 0 {
		return port.Principal{}, false, fmt.Errorf("%w: profile for %s has no config", port.ErrAuthInternal, key)
	}

	if profileUID != nil {
		profile = append(json.RawMessage(nil), profileConfig...)

		kek, err = i.openProfileKEK(*profileUID, profileKekN, profileKekC)
		if err != nil {
			return port.Principal{}, false, fmt.Errorf("%w: decrypt profile KEK for %s: %w", port.ErrAuthInternal, key, err)
		}
	}

	s3Target, err := i.principalTarget(targetUID, targetName, targetConfig, tSecretN, tSecretC, tSessionN, tSessionC)
	if err != nil {
		return port.Principal{}, false, fmt.Errorf("%w: %w", port.ErrAuthInternal, err)
	}

	principal := port.Principal{
		AccessKeyID:    key,
		SecretKey:      secret,
		AllowedBuckets: []string{i.bucket},
		User: port.UserPolicy{
			ID:            id,
			Prefix:        prefix,
			Encryption:    profile,
			EncryptionKEK: kek,
			Target:        s3Target,
		},
	}

	i.cache.put(key, principal)

	return principal, true, nil
}

func (i *Identity) principalTarget(targetUID, targetName *string, config, secretN, secretC, sessionN, sessionC []byte) (*port.S3Target, error) {
	if targetUID == nil {
		return nil, nil
	}

	t, err := i.openTarget(*targetUID, derefString(targetName), string(config), secretN, secretC, sessionN, sessionC)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

// Allow authorizes one operation. It never touches the database: the policy was
// resolved by Lookup, and the transparent prefix is applied by the request
// scope. Here we only reject operations outside the virtual bucket and keys
// that could escape the key space.
func (i *Identity) Allow(_ context.Context, p port.Principal, op port.S3Op, bucket, key string) error {
	if p.User.ID == 0 || !keying.IsCanonicalPrefix(p.User.Prefix) {
		return port.ErrAccessDenied
	}

	if op == port.S3OpListBuckets {
		return nil
	}

	if !strings.EqualFold(bucket, i.bucket) {
		return port.ErrAccessDenied
	}

	switch op {
	case port.S3OpHeadBucket, port.S3OpList:
		return nil
	case port.S3OpGet, port.S3OpHead, port.S3OpPut, port.S3OpDelete,
		port.S3OpCreateMultipartUpload, port.S3OpUploadPart,
		port.S3OpCompleteMultipartUpload, port.S3OpAbortMultipartUpload,
		port.S3OpListParts:
		if key == "" {
			return port.ErrAccessDenied
		}

		if _, err := keying.ValidateRelative(key); err != nil {
			return port.ErrAccessDenied
		}

		return nil
	case port.S3OpUnknown, port.S3OpListBuckets:
		return port.ErrAccessDenied
	default:
		return port.ErrAccessDenied
	}
}
