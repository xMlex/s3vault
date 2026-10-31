package postgres

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xMlex/s3vault/internal/adapter/s3auth/secretbox"
	"github.com/xMlex/s3vault/internal/adapter/s3target"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/port"
)

// ErrUserNotFound is returned by admin operations that address an unknown key.
var ErrUserNotFound = errors.New("postgres auth: user not found")

// EncryptionProfileRef is the profile a user references, as shown by
// `user list`. The config is not secret; key files are referenced by path.
type EncryptionProfileRef struct {
	UID    string
	Name   string
	Config json.RawMessage
}

// User is the admin-facing row. The frontend secret is deliberately absent: it
// is shown once by Add/Rotate and never read back.
type User struct {
	ID                int64
	Name              string
	AccessKeyID       string
	Prefix            string
	EncryptionProfile *EncryptionProfileRef
	Target            *TargetInfo
	Enabled           bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// AddParams creates one user. Empty AccessKeyID means "generate". Empty
// EncryptionProfileName/TargetName mean the gateway's global profile/S3.
type AddParams struct {
	Name                  string
	AccessKeyID           string
	Prefix                string
	EncryptionProfileName string
	TargetName            string
}

// UpdateParams changes the namespace, profile or destination of an existing
// user. Nil Prefix means "keep". Nil EncryptionProfileName/TargetName mean
// "keep"; Clear* sets the reference to NULL.
type UpdateParams struct {
	Prefix                *string
	EncryptionProfileName *string
	ClearEncryption       bool
	TargetName            *string
	ClearTarget           bool
}

const userSelect = `SELECT u.id, u.name, u.access_key_id, u.prefix,
	                u.enabled, u.created_at, u.updated_at,
	                p.uid, p.name, p.config,
	                t.uid, t.name, t.created_at, t.updated_at, t.config
	           FROM s3vault_users u
	           LEFT JOIN s3vault_encryption_profiles p ON p.uid = u.encryption_profile_uid
	           LEFT JOIN s3vault_targets t ON t.uid = u.s3_target_uid`

// ListUsers returns all users without secrets.
func (i *Identity) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := i.pool.Query(ctx, userSelect+` ORDER BY u.id`)
	if err != nil {
		return nil, fmt.Errorf("postgres auth: list users: %w", err)
	}
	defer rows.Close()

	var users []User

	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}

		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres auth: list users rows: %w", err)
	}

	return users, nil
}

// AddUser inserts a user and returns the generated secret once.
//
//nolint:gocyclo // validation, profile/target resolution and the overlap transaction are one insert flow.
func (i *Identity) AddUser(ctx context.Context, p AddParams) (User, string, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return User{}, "", errors.New("postgres auth: name is required")
	}

	prefix, err := keying.NormalizePrefix(p.Prefix)
	if err != nil {
		return User{}, "", fmt.Errorf("postgres auth: prefix: %w", err)
	}

	accessKey := strings.TrimSpace(p.AccessKeyID)
	if accessKey == "" {
		accessKey, err = newAccessKey()
		if err != nil {
			return User{}, "", err
		}
	} else if err := validateAccessKey(accessKey); err != nil {
		return User{}, "", err
	}

	secret, err := secretbox.GenerateSecret()
	if err != nil {
		return User{}, "", err
	}

	nonce, ciphertext, err := i.sealSecret(accessKey, secret)
	if err != nil {
		return User{}, "", fmt.Errorf("postgres auth: encrypt secret: %w", err)
	}

	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return User{}, "", fmt.Errorf("postgres auth: begin add user: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", userMutationLockID); err != nil {
		return User{}, "", fmt.Errorf("postgres auth: add user lock: %w", err)
	}

	if err := checkPrefixOverlap(ctx, tx, prefix, ""); err != nil {
		return User{}, "", err
	}

	var profileUID, targetUID *string

	if p.EncryptionProfileName != "" {
		uid, err := resolveEncryptionProfileUID(ctx, tx, p.EncryptionProfileName)
		if err != nil {
			return User{}, "", err
		}

		profileUID = &uid
	}

	if p.TargetName != "" {
		uid, err := resolveTargetUID(ctx, tx, p.TargetName)
		if err != nil {
			return User{}, "", err
		}

		targetUID = &uid
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO s3vault_users
		    (name, access_key_id, secret_key_nonce, secret_key_ciphertext, prefix,
		     encryption_profile_uid, s3_target_uid)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		name, accessKey, nonce, ciphertext, prefix, profileUID, targetUID,
	); err != nil {
		if isUniqueViolation(err) {
			return User{}, "", errors.New("postgres auth: user name or access key already exists")
		}

		return User{}, "", fmt.Errorf("postgres auth: insert user: %w", err)
	}

	u, err := loadUser(ctx, tx, accessKey)
	if err != nil {
		return User{}, "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return User{}, "", fmt.Errorf("postgres auth: commit add user: %w", err)
	}

	return u, secret, nil
}

// RotateSecret replaces a user's frontend secret and returns the new value once.
func (i *Identity) RotateSecret(ctx context.Context, accessKeyID string) (string, error) {
	secret, err := secretbox.GenerateSecret()
	if err != nil {
		return "", err
	}

	nonce, ciphertext, err := i.sealSecret(accessKeyID, secret)
	if err != nil {
		return "", fmt.Errorf("postgres auth: encrypt secret: %w", err)
	}

	tag, err := i.pool.Exec(ctx,
		`UPDATE s3vault_users
		    SET secret_key_nonce = $2, secret_key_ciphertext = $3, updated_at = now()
		  WHERE access_key_id = $1`,
		accessKeyID, nonce, ciphertext,
	)
	if err != nil {
		return "", fmt.Errorf("postgres auth: rotate secret: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return "", ErrUserNotFound
	}

	return secret, nil
}

// SetEnabled enables or disables a user. Disabling is the supported alternative
// to deleting a row because the user's objects stay addressable for re-enabling.
func (i *Identity) SetEnabled(ctx context.Context, accessKeyID string, enabled bool) error {
	tag, err := i.pool.Exec(ctx,
		`UPDATE s3vault_users SET enabled = $2, updated_at = now() WHERE access_key_id = $1`,
		accessKeyID, enabled,
	)
	if err != nil {
		return fmt.Errorf("postgres auth: set enabled: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}

// UpdateUser changes the prefix, encryption profile and/or destination.
//
//nolint:gocyclo // one transaction keeps the three update dimensions and their mutual exclusions together.
func (i *Identity) UpdateUser(ctx context.Context, accessKeyID string, p UpdateParams) (User, error) {
	if p.ClearTarget && p.TargetName != nil {
		return User{}, errors.New("postgres auth: target and clear-target are mutually exclusive")
	}

	if p.ClearEncryption && p.EncryptionProfileName != nil {
		return User{}, errors.New("postgres auth: encryption profile and clear-encryption are mutually exclusive")
	}

	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("postgres auth: begin update user: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", userMutationLockID); err != nil {
		return User{}, fmt.Errorf("postgres auth: update user lock: %w", err)
	}

	var (
		prefix     string
		profileUID *string
		targetUID  *string
	)

	err = tx.QueryRow(ctx,
		`SELECT prefix, encryption_profile_uid, s3_target_uid
		   FROM s3vault_users WHERE access_key_id = $1 FOR UPDATE`, accessKeyID,
	).Scan(&prefix, &profileUID, &targetUID)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}

	if err != nil {
		return User{}, fmt.Errorf("postgres auth: load user: %w", err)
	}

	newPrefix := prefix
	if p.Prefix != nil {
		newPrefix, err = keying.NormalizePrefix(*p.Prefix)
		if err != nil {
			return User{}, fmt.Errorf("postgres auth: prefix: %w", err)
		}
	}

	newProfile := profileUID

	switch {
	case p.ClearEncryption:
		newProfile = nil
	case p.EncryptionProfileName != nil:
		uid, err := resolveEncryptionProfileUID(ctx, tx, *p.EncryptionProfileName)
		if err != nil {
			return User{}, err
		}

		newProfile = &uid
	}

	newTarget := targetUID

	switch {
	case p.ClearTarget:
		newTarget = nil
	case p.TargetName != nil:
		uid, err := resolveTargetUID(ctx, tx, *p.TargetName)
		if err != nil {
			return User{}, err
		}

		newTarget = &uid
	}

	if newPrefix != prefix {
		if err := checkPrefixOverlap(ctx, tx, newPrefix, accessKeyID); err != nil {
			return User{}, err
		}
	}

	if _, err := tx.Exec(ctx,
		`UPDATE s3vault_users
		    SET prefix = $2, encryption_profile_uid = $3, s3_target_uid = $4, updated_at = now()
		  WHERE access_key_id = $1`,
		accessKeyID, newPrefix, newProfile, newTarget,
	); err != nil {
		return User{}, fmt.Errorf("postgres auth: update user: %w", err)
	}

	u, err := loadUser(ctx, tx, accessKeyID)
	if err != nil {
		return User{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("postgres auth: commit update user: %w", err)
	}

	return u, nil
}

func loadUser(ctx context.Context, tx pgx.Tx, accessKeyID string) (User, error) {
	u, err := scanUser(tx.QueryRow(ctx, userSelect+` WHERE u.access_key_id = $1`, accessKeyID))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}

	if err != nil {
		return User{}, fmt.Errorf("postgres auth: load user: %w", err)
	}

	return u, nil
}

func (i *Identity) sealTarget(uid string, t *port.S3Target) (config, secretN, secretC, sessionN, sessionC []byte, err error) {
	if t == nil {
		return nil, nil, nil, nil, nil, nil
	}

	config, err = s3target.StoredJSON(*t)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("postgres auth: target: %w", err)
	}

	secretN, secretC, err = i.sealTargetSecret(uid, t.SecretKey)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("postgres auth: encrypt target secret: %w", err)
	}

	sessionN, sessionC, err = i.sealTargetSession(uid, t.SessionToken)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("postgres auth: encrypt target session token: %w", err)
	}

	return config, secretN, secretC, sessionN, sessionC, nil
}

func checkPrefixOverlap(ctx context.Context, tx pgx.Tx, prefix, excludeKey string) error {
	rows, err := tx.Query(ctx,
		`SELECT access_key_id, prefix FROM s3vault_users WHERE access_key_id <> $1`,
		excludeKey,
	)
	if err != nil {
		return fmt.Errorf("postgres auth: check prefixes: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var key, other string
		if err := rows.Scan(&key, &other); err != nil {
			return fmt.Errorf("postgres auth: check prefixes scan: %w", err)
		}

		if keying.PrefixesOverlap(prefix, other) {
			return fmt.Errorf("postgres auth: prefix %q overlaps user %s prefix %q", prefix, key, other)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres auth: check prefixes rows: %w", err)
	}

	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (User, error) {
	var (
		u                       User
		profileUID, profileName *string
		profileConfig           []byte
		targetUID, targetName   *string
		targetCreated           *time.Time
		targetUpdated           *time.Time
		targetConfig            []byte
	)

	if err := row.Scan(&u.ID, &u.Name, &u.AccessKeyID, &u.Prefix,
		&u.Enabled, &u.CreatedAt, &u.UpdatedAt,
		&profileUID, &profileName, &profileConfig,
		&targetUID, &targetName, &targetCreated, &targetUpdated, &targetConfig); err != nil {
		return User{}, err
	}

	if profileUID != nil {
		u.EncryptionProfile = &EncryptionProfileRef{
			UID:    *profileUID,
			Name:   derefString(profileName),
			Config: append(json.RawMessage(nil), profileConfig...),
		}
	}

	if targetUID != nil {
		t, err := s3target.DecodeStored(targetConfig)
		if err != nil {
			return User{}, fmt.Errorf("postgres auth: user %s target: %w", u.AccessKeyID, err)
		}

		info := &TargetInfo{
			UID:          *targetUID,
			Name:         derefString(targetName),
			Endpoint:     t.Endpoint,
			Region:       t.Region,
			Bucket:       t.Bucket,
			Prefix:       t.Prefix,
			PathStyle:    t.PathStyle,
			AccessKey:    t.AccessKey,
			SSEKMS:       t.SSEKMS,
			StorageClass: t.StorageClass,
		}
		if targetCreated != nil {
			info.CreatedAt = *targetCreated
		}

		if targetUpdated != nil {
			info.UpdatedAt = *targetUpdated
		}

		u.Target = info
	}

	return u, nil
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}

	return *p
}

const accessKeyAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func newAccessKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("access key: %w", err)
	}

	for idx, v := range b {
		b[idx] = accessKeyAlphabet[int(v)%len(accessKeyAlphabet)]
	}

	return "S3V" + string(b), nil
}

func validateAccessKey(key string) error {
	if len(key) < 16 || len(key) > 128 {
		return fmt.Errorf("postgres auth: access_key_id must be 16..128 bytes, got %d", len(key))
	}

	for _, r := range key {
		if r <= ' ' || r == 0x7f {
			return errors.New("postgres auth: access_key_id contains whitespace or control characters")
		}
	}

	return nil
}
