package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xMlex/s3vault/internal/adapter/s3target"
	"github.com/xMlex/s3vault/internal/port"
)

// Registry errors. They are returned to the CLI with a readable message and
// never contain a secret.
var (
	ErrTargetNotFound            = errors.New("postgres auth: target not found")
	ErrEncryptionProfileNotFound = errors.New("postgres auth: encryption profile not found")
	ErrTargetInUse               = errors.New("postgres auth: target is assigned to users")
	ErrEncryptionProfileInUse    = errors.New("postgres auth: encryption profile is assigned to users")
)

const entityNameMax = 128

// TargetInfo is the admin-facing, non-secret view of a shared destination.
type TargetInfo struct {
	UID          string
	Name         string
	Endpoint     string
	Region       string
	Bucket       string
	Prefix       string
	PathStyle    bool
	AccessKey    string
	SSEKMS       *port.SSEKMS
	StorageClass string
	Users        int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// EncryptionProfile is the admin-facing view of a shared encryption profile.
type EncryptionProfile struct {
	UID       string
	Name      string
	Config    json.RawMessage
	Users     int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

const targetSelect = `SELECT t.uid, t.name, t.config, t.created_at, t.updated_at,
	                (SELECT count(*) FROM s3vault_users u WHERE u.s3_target_uid = t.uid)
	           FROM s3vault_targets t`

// AddTarget creates a shared destination and returns its non-secret view.
func (i *Identity) AddTarget(ctx context.Context, name string, t port.S3Target) (TargetInfo, error) {
	name, err := normalizeEntityName(name)
	if err != nil {
		return TargetInfo{}, err
	}

	uid, err := newEntityUID()
	if err != nil {
		return TargetInfo{}, err
	}

	config, secretN, secretC, sessionN, sessionC, err := i.sealTarget(uid, &t)
	if err != nil {
		return TargetInfo{}, err
	}

	row := i.pool.QueryRow(ctx,
		`INSERT INTO s3vault_targets
		    (uid, name, config, secret_nonce, secret_ciphertext, session_nonce, session_ciphertext)
		 VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7)
		 RETURNING uid, name, config, created_at, updated_at`,
		uid, name, config, secretN, secretC, sessionN, sessionC,
	)

	info, err := scanTarget(row)
	if err != nil {
		if isUniqueViolation(err) {
			return TargetInfo{}, fmt.Errorf("postgres auth: target name %q already exists", name)
		}

		return TargetInfo{}, fmt.Errorf("postgres auth: add target: %w", err)
	}

	return info, nil
}

// ListTargets returns all shared destinations without their secrets.
func (i *Identity) ListTargets(ctx context.Context) ([]TargetInfo, error) {
	rows, err := i.pool.Query(ctx, targetSelect+` ORDER BY t.name`)
	if err != nil {
		return nil, fmt.Errorf("postgres auth: list targets: %w", err)
	}
	defer rows.Close()

	var targets []TargetInfo

	for rows.Next() {
		t, err := scanTargetWithUsers(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres auth: list targets: %w", err)
		}

		targets = append(targets, t)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres auth: list targets rows: %w", err)
	}

	return targets, nil
}

// UpdateTarget fully replaces a target under the same uid. The uid is the AAD
// domain, so renaming or rotating the secret does not change how the row is
// decrypted; the pool and multipart snapshots see a new fingerprint instead.
func (i *Identity) UpdateTarget(ctx context.Context, name string, t port.S3Target, newName string) (TargetInfo, error) {
	name, err := normalizeEntityName(name)
	if err != nil {
		return TargetInfo{}, err
	}

	if newName == "" {
		newName = name
	} else if newName, err = normalizeEntityName(newName); err != nil {
		return TargetInfo{}, err
	}

	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return TargetInfo{}, fmt.Errorf("postgres auth: begin update target: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", userMutationLockID); err != nil {
		return TargetInfo{}, fmt.Errorf("postgres auth: update target lock: %w", err)
	}

	var uid string
	if err := tx.QueryRow(ctx,
		`SELECT uid FROM s3vault_targets WHERE name = $1 FOR UPDATE`, name,
	).Scan(&uid); errors.Is(err, pgx.ErrNoRows) {
		return TargetInfo{}, ErrTargetNotFound
	} else if err != nil {
		return TargetInfo{}, fmt.Errorf("postgres auth: load target: %w", err)
	}

	config, secretN, secretC, sessionN, sessionC, err := i.sealTarget(uid, &t)
	if err != nil {
		return TargetInfo{}, err
	}

	row := tx.QueryRow(ctx,
		`UPDATE s3vault_targets
		    SET name = $2, config = $3::jsonb,
		        secret_nonce = $4, secret_ciphertext = $5,
		        session_nonce = $6, session_ciphertext = $7,
		        updated_at = now()
		  WHERE uid = $1
		 RETURNING uid, name, config, created_at, updated_at`,
		uid, newName, config, secretN, secretC, sessionN, sessionC,
	)

	info, err := scanTarget(row)
	if err != nil {
		if isUniqueViolation(err) {
			return TargetInfo{}, fmt.Errorf("postgres auth: target name %q already exists", newName)
		}

		return TargetInfo{}, fmt.Errorf("postgres auth: update target: %w", err)
	}

	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM s3vault_users WHERE s3_target_uid = $1`, uid,
	).Scan(&info.Users); err != nil {
		return TargetInfo{}, fmt.Errorf("postgres auth: count target users: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return TargetInfo{}, fmt.Errorf("postgres auth: commit update target: %w", err)
	}

	return info, nil
}

// RemoveTarget deletes a target only when no user references it.
func (i *Identity) RemoveTarget(ctx context.Context, name string) error {
	return i.removeSharedEntity(ctx, name, sharedEntity{
		table:      "s3vault_targets",
		userColumn: "s3_target_uid",
		notFound:   ErrTargetNotFound,
		inUse:      ErrTargetInUse,
	})
}

// AddEncryptionProfile creates a shared encryption profile.
func (i *Identity) AddEncryptionProfile(ctx context.Context, name string, config json.RawMessage) (EncryptionProfile, error) {
	name, err := normalizeEntityName(name)
	if err != nil {
		return EncryptionProfile{}, err
	}

	config, err = i.normalizeProfileConfig(config)
	if err != nil {
		return EncryptionProfile{}, err
	}

	uid, err := newEntityUID()
	if err != nil {
		return EncryptionProfile{}, err
	}

	row := i.pool.QueryRow(ctx,
		`INSERT INTO s3vault_encryption_profiles (uid, name, config)
		 VALUES ($1, $2, $3::jsonb)
		 RETURNING uid, name, config, created_at, updated_at`,
		uid, name, string(config),
	)

	p, err := scanProfile(row)
	if err != nil {
		if isUniqueViolation(err) {
			return EncryptionProfile{}, fmt.Errorf("postgres auth: encryption profile name %q already exists", name)
		}

		return EncryptionProfile{}, fmt.Errorf("postgres auth: add encryption profile: %w", err)
	}

	return p, nil
}

// ListEncryptionProfiles returns all shared profiles.
func (i *Identity) ListEncryptionProfiles(ctx context.Context) ([]EncryptionProfile, error) {
	rows, err := i.pool.Query(ctx,
		`SELECT p.uid, p.name, p.config, p.created_at, p.updated_at,
		        (SELECT count(*) FROM s3vault_users u WHERE u.encryption_profile_uid = p.uid)
		   FROM s3vault_encryption_profiles p
		  ORDER BY p.name`)
	if err != nil {
		return nil, fmt.Errorf("postgres auth: list encryption profiles: %w", err)
	}
	defer rows.Close()

	var profiles []EncryptionProfile

	for rows.Next() {
		p, err := scanProfileWithUsers(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres auth: list encryption profiles: %w", err)
		}

		profiles = append(profiles, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres auth: list encryption profiles rows: %w", err)
	}

	return profiles, nil
}

// UpdateEncryptionProfile fully replaces a profile under the same uid.
func (i *Identity) UpdateEncryptionProfile(ctx context.Context, name string, config json.RawMessage, newName string) (EncryptionProfile, error) {
	name, err := normalizeEntityName(name)
	if err != nil {
		return EncryptionProfile{}, err
	}

	if newName == "" {
		newName = name
	} else if newName, err = normalizeEntityName(newName); err != nil {
		return EncryptionProfile{}, err
	}

	config, err = i.normalizeProfileConfig(config)
	if err != nil {
		return EncryptionProfile{}, err
	}

	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return EncryptionProfile{}, fmt.Errorf("postgres auth: begin update profile: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", userMutationLockID); err != nil {
		return EncryptionProfile{}, fmt.Errorf("postgres auth: update profile lock: %w", err)
	}

	var uid string
	if err := tx.QueryRow(ctx,
		`SELECT uid FROM s3vault_encryption_profiles WHERE name = $1 FOR UPDATE`, name,
	).Scan(&uid); errors.Is(err, pgx.ErrNoRows) {
		return EncryptionProfile{}, ErrEncryptionProfileNotFound
	} else if err != nil {
		return EncryptionProfile{}, fmt.Errorf("postgres auth: load profile: %w", err)
	}

	row := tx.QueryRow(ctx,
		`UPDATE s3vault_encryption_profiles
		    SET name = $2, config = $3::jsonb, updated_at = now()
		  WHERE uid = $1
		 RETURNING uid, name, config, created_at, updated_at`,
		uid, newName, string(config),
	)

	p, err := scanProfile(row)
	if err != nil {
		if isUniqueViolation(err) {
			return EncryptionProfile{}, fmt.Errorf("postgres auth: encryption profile name %q already exists", newName)
		}

		return EncryptionProfile{}, fmt.Errorf("postgres auth: update profile: %w", err)
	}

	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM s3vault_users WHERE encryption_profile_uid = $1`, uid,
	).Scan(&p.Users); err != nil {
		return EncryptionProfile{}, fmt.Errorf("postgres auth: count profile users: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return EncryptionProfile{}, fmt.Errorf("postgres auth: commit update profile: %w", err)
	}

	return p, nil
}

// RemoveEncryptionProfile deletes a profile only when no user references it.
func (i *Identity) RemoveEncryptionProfile(ctx context.Context, name string) error {
	return i.removeSharedEntity(ctx, name, sharedEntity{
		table:      "s3vault_encryption_profiles",
		userColumn: "encryption_profile_uid",
		notFound:   ErrEncryptionProfileNotFound,
		inUse:      ErrEncryptionProfileInUse,
	})
}

type sharedEntity struct {
	table      string // trusted internal constant, never user input
	userColumn string // trusted internal constant
	notFound   error
	inUse      error
}

func (i *Identity) removeSharedEntity(ctx context.Context, name string, e sharedEntity) error {
	name, err := normalizeEntityName(name)
	if err != nil {
		return err
	}

	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres auth: begin remove %s: %w", e.table, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", userMutationLockID); err != nil {
		return fmt.Errorf("postgres auth: remove %s lock: %w", e.table, err)
	}

	var uid string
	if err := tx.QueryRow(ctx,
		`SELECT uid FROM `+e.table+` WHERE name = $1 FOR UPDATE`, name,
	).Scan(&uid); errors.Is(err, pgx.ErrNoRows) {
		return e.notFound
	} else if err != nil {
		return fmt.Errorf("postgres auth: load %s: %w", e.table, err)
	}

	var users int64
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM s3vault_users WHERE `+e.userColumn+` = $1`, uid,
	).Scan(&users); err != nil {
		return fmt.Errorf("postgres auth: count %s users: %w", e.table, err)
	}

	if users > 0 {
		return fmt.Errorf("%w: %s (%d user(s))", e.inUse, name, users)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM `+e.table+` WHERE uid = $1`, uid); err != nil {
		return fmt.Errorf("postgres auth: remove %s: %w", e.table, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres auth: commit remove %s: %w", e.table, err)
	}

	return nil
}

func (i *Identity) normalizeProfileConfig(raw json.RawMessage) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || isGlobalEncryption(trimmed) {
		return nil, errors.New("postgres auth: encryption profile must have a non-empty mode")
	}

	var probe struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return nil, fmt.Errorf("postgres auth: encryption profile: %w", err)
	}

	if strings.TrimSpace(probe.Mode) == "" {
		return nil, errors.New("postgres auth: encryption profile must have a non-empty mode")
	}

	if i.validateEnc != nil {
		if err := i.validateEnc(trimmed); err != nil {
			return nil, err
		}
	}

	return append(json.RawMessage(nil), trimmed...), nil
}

func resolveEncryptionProfileUID(ctx context.Context, tx pgx.Tx, name string) (string, error) {
	name, err := normalizeEntityName(name)
	if err != nil {
		return "", err
	}

	var uid string
	if err := tx.QueryRow(ctx,
		`SELECT uid FROM s3vault_encryption_profiles WHERE name = $1`, name,
	).Scan(&uid); errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: %s", ErrEncryptionProfileNotFound, name)
	} else if err != nil {
		return "", fmt.Errorf("postgres auth: resolve encryption profile: %w", err)
	}

	return uid, nil
}

func resolveTargetUID(ctx context.Context, tx pgx.Tx, name string) (string, error) {
	name, err := normalizeEntityName(name)
	if err != nil {
		return "", err
	}

	var uid string
	if err := tx.QueryRow(ctx,
		`SELECT uid FROM s3vault_targets WHERE name = $1`, name,
	).Scan(&uid); errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: %s", ErrTargetNotFound, name)
	} else if err != nil {
		return "", fmt.Errorf("postgres auth: resolve target: %w", err)
	}

	return uid, nil
}

func scanTarget(row scanner) (TargetInfo, error) {
	var (
		info      TargetInfo
		config    []byte
		createdAt time.Time
		updatedAt time.Time
	)

	if err := row.Scan(&info.UID, &info.Name, &config, &createdAt, &updatedAt); err != nil {
		return TargetInfo{}, err
	}

	info.CreatedAt = createdAt
	info.UpdatedAt = updatedAt

	if err := decodeTargetInfo(&info, config); err != nil {
		return TargetInfo{}, err
	}

	return info, nil
}

func scanTargetWithUsers(row scanner) (TargetInfo, error) {
	var (
		info      TargetInfo
		config    []byte
		createdAt time.Time
		updatedAt time.Time
		users     int64
	)

	if err := row.Scan(&info.UID, &info.Name, &config, &createdAt, &updatedAt, &users); err != nil {
		return TargetInfo{}, err
	}

	info.CreatedAt = createdAt
	info.UpdatedAt = updatedAt
	info.Users = users

	if err := decodeTargetInfo(&info, config); err != nil {
		return TargetInfo{}, err
	}

	return info, nil
}

func decodeTargetInfo(info *TargetInfo, config []byte) error {
	t, err := s3target.DecodeStored(config)
	if err != nil {
		return fmt.Errorf("target %s: %w", info.Name, err)
	}

	info.Endpoint = t.Endpoint
	info.Region = t.Region
	info.Bucket = t.Bucket
	info.Prefix = t.Prefix
	info.PathStyle = t.PathStyle
	info.AccessKey = t.AccessKey
	info.SSEKMS = t.SSEKMS
	info.StorageClass = t.StorageClass

	return nil
}

func scanProfile(row scanner) (EncryptionProfile, error) {
	var (
		p      EncryptionProfile
		config []byte
	)

	if err := row.Scan(&p.UID, &p.Name, &config, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return EncryptionProfile{}, err
	}

	p.Config = append(json.RawMessage(nil), config...)

	return p, nil
}

func scanProfileWithUsers(row scanner) (EncryptionProfile, error) {
	var (
		p      EncryptionProfile
		config []byte
	)

	if err := row.Scan(&p.UID, &p.Name, &config, &p.CreatedAt, &p.UpdatedAt, &p.Users); err != nil {
		return EncryptionProfile{}, err
	}

	p.Config = append(json.RawMessage(nil), config...)

	return p, nil
}

func normalizeEntityName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("postgres auth: name is required")
	}

	if len(name) > entityNameMax {
		return "", fmt.Errorf("postgres auth: name is %d bytes, over the %d byte limit", len(name), entityNameMax)
	}

	for _, r := range name {
		if r < ' ' || r == 0x7f {
			return "", errors.New("postgres auth: name contains control characters")
		}
	}

	return name, nil
}

func newEntityUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("postgres auth: entity uid: %w", err)
	}

	return hex.EncodeToString(b[:]), nil
}

// isGlobalEncryption reports whether a profile value means "use the gateway
// profile": absent, null, {}, or an empty mode. Such a value is never stored in
// the registry.
func isGlobalEncryption(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("{}")) {
		return true
	}

	var p struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(trimmed, &p); err == nil && strings.TrimSpace(p.Mode) == "" {
		return true
	}

	return false
}
