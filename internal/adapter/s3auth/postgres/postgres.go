// Package postgres implements the gateway's S3 identity from PostgreSQL.
package postgres

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xMlex/s3vault/internal/adapter/s3auth/secretbox"
	"github.com/xMlex/s3vault/internal/adapter/s3target"
	"github.com/xMlex/s3vault/internal/keying"
	"github.com/xMlex/s3vault/internal/port"
)

// MasterKeyEnv is the only place the master key is read from. It is not a
// Config field: a secret must not be accepted from YAML.
const MasterKeyEnv = "S3VAULT_SERVER_AUTH_MASTER_KEY"

// Advisory lock IDs are deliberately fixed: every process and every admin
// command must agree on them.
const (
	migrationLockID    int64 = 723846239
	userMutationLockID int64 = 723846240
)

const (
	defaultQueryTimeout = 2 * time.Second
	defaultMaxConns     = int32(8)
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Config opens the identity backend.
type Config struct {
	DSN                string
	MaxConns           int32
	QueryTimeout       time.Duration
	MasterKey          []byte
	Bucket             string
	Logger             *slog.Logger
	ValidateEncryption func(json.RawMessage) error
	// SkipValidation disables the startup pass over existing rows. The server
	// must leave it false; admin commands use it so one corrupt user, profile or
	// target cannot lock the operator out of listing or removing it.
	SkipValidation bool
}

// Identity is a PostgreSQL-backed port.S3Identity.
type Identity struct {
	pool        *pgxpool.Pool
	bucket      string
	timeout     time.Duration
	masterKey   []byte
	log         *slog.Logger
	validateEnc func(json.RawMessage) error
}

// Open connects, migrates, and validates every existing user. Any failure is
// fatal for the gateway: a database that cannot be trusted at startup must not
// serve requests later.
func Open(ctx context.Context, cfg Config) (*Identity, error) {
	if strings.TrimSpace(cfg.DSN) == "" {
		return nil, errors.New("postgres auth: dsn is required")
	}

	if len(cfg.MasterKey) != secretbox.KeySize {
		return nil, fmt.Errorf("postgres auth: master key must be %d bytes, got %d", secretbox.KeySize, len(cfg.MasterKey))
	}

	if cfg.Bucket == "" {
		return nil, errors.New("postgres auth: virtual bucket is required")
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("postgres auth: parse dsn: %w", err)
	}

	poolCfg.ConnConfig.ConnectTimeout = 5 * time.Second
	poolCfg.ConnConfig.RuntimeParams["application_name"] = "s3vault"

	poolCfg.MaxConns = cfg.MaxConns
	if poolCfg.MaxConns <= 0 {
		poolCfg.MaxConns = defaultMaxConns
	}

	poolCfg.MaxConnLifetime = 30 * time.Minute
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("postgres auth: pool: %w", err)
	}

	timeout := cfg.QueryTimeout
	if timeout <= 0 {
		timeout = defaultQueryTimeout
	}

	id := &Identity{
		pool:        pool,
		bucket:      cfg.Bucket,
		timeout:     timeout,
		masterKey:   append([]byte(nil), cfg.MasterKey...),
		log:         cfg.Logger,
		validateEnc: cfg.ValidateEncryption,
	}
	if id.log == nil {
		id.log = slog.Default()
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = pool.Ping(pingCtx)

	cancel()

	if err != nil {
		pool.Close()

		return nil, fmt.Errorf("postgres auth: ping: %w", err)
	}

	if err := id.migrate(ctx); err != nil {
		pool.Close()

		return nil, err
	}

	if !cfg.SkipValidation {
		if err := id.validateAll(ctx); err != nil {
			pool.Close()

			return nil, err
		}
	}

	return id, nil
}

// Close releases the pool.
func (i *Identity) Close() {
	if i != nil && i.pool != nil {
		i.pool.Close()
	}
}

// Ping checks the database for readiness.
func (i *Identity) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, i.timeout)
	defer cancel()

	return i.pool.Ping(ctx)
}

// migrate applies the embedded migrations under a fixed advisory lock.
func (i *Identity) migrate(ctx context.Context) error {
	conn, err := i.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("postgres auth: acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("postgres auth: migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockID)
	}()

	return i.applyMigrations(ctx, conn)
}

//nolint:gocyclo // migration error branches name the exact step and must all be handled.
func (i *Identity) applyMigrations(ctx context.Context, conn *pgxpool.Conn) error {
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS s3vault_schema_migrations (
		version bigint PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("postgres auth: migration table: %w", err)
	}

	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return fmt.Errorf("postgres auth: read migrations: %w", err)
	}

	sort.Slice(entries, func(a, b int) bool { return entries[a].Name() < entries[b].Name() })

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}

		version, err := migrationVersion(entry.Name())
		if err != nil {
			return err
		}

		var exists bool
		if err := conn.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM s3vault_schema_migrations WHERE version = $1)`, version,
		).Scan(&exists); err != nil {
			return fmt.Errorf("postgres auth: migration %d check: %w", version, err)
		}

		if exists {
			continue
		}

		body, err := migrationFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("postgres auth: read migration %s: %w", entry.Name(), err)
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("postgres auth: begin migration %d: %w", version, err)
		}

		if _, err := tx.Exec(ctx, string(body), pgx.QueryExecModeSimpleProtocol); err != nil {
			_ = tx.Rollback(ctx)

			return fmt.Errorf("postgres auth: apply migration %d: %w", version, err)
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO s3vault_schema_migrations (version) VALUES ($1)`, version,
		); err != nil {
			_ = tx.Rollback(ctx)

			return fmt.Errorf("postgres auth: record migration %d: %w", version, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("postgres auth: commit migration %d: %w", version, err)
		}
	}

	return nil
}

func migrationVersion(name string) (int64, error) {
	base := strings.TrimSuffix(name, ".sql")

	prefix, _, ok := strings.Cut(base, "_")
	if !ok {
		return 0, fmt.Errorf("postgres auth: migration %q has no numeric prefix", name)
	}

	v, err := strconv.ParseInt(prefix, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("postgres auth: migration %q: %w", name, err)
	}

	return v, nil
}

// validateAll is the startup fail-fast pass described in spec/db-users.md §6.3.
func (i *Identity) validateAll(ctx context.Context) error {
	conn, err := i.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("postgres auth: acquire validation connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", userMutationLockID); err != nil {
		return fmt.Errorf("postgres auth: validation lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", userMutationLockID)
	}()

	if err := i.validateProfiles(ctx, conn); err != nil {
		return err
	}

	if err := i.validateTargets(ctx, conn); err != nil {
		return err
	}

	return i.validateUsers(ctx, conn)
}

func (i *Identity) validateProfiles(ctx context.Context, conn *pgxpool.Conn) error {
	rows, err := conn.Query(ctx,
		`SELECT name, config FROM s3vault_encryption_profiles ORDER BY name`)
	if err != nil {
		return fmt.Errorf("postgres auth: validate profiles: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			name   string
			config []byte
		)
		if err := rows.Scan(&name, &config); err != nil {
			return fmt.Errorf("postgres auth: validate profile scan: %w", err)
		}

		if len(config) == 0 || isGlobalEncryption(config) {
			return fmt.Errorf("postgres auth: encryption profile %s has an empty config", name)
		}

		if i.validateEnc != nil {
			if err := i.validateEnc(json.RawMessage(config)); err != nil {
				return fmt.Errorf("postgres auth: encryption profile %s: %w", name, err)
			}
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres auth: validate profiles rows: %w", err)
	}

	return nil
}

func (i *Identity) validateTargets(ctx context.Context, conn *pgxpool.Conn) error {
	rows, err := conn.Query(ctx,
		`SELECT uid, name, config, secret_nonce, secret_ciphertext,
		        session_nonce, session_ciphertext
		   FROM s3vault_targets ORDER BY name`)
	if err != nil {
		return fmt.Errorf("postgres auth: validate targets: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			uid, name          string
			config             []byte
			secretN, secretC   []byte
			sessionN, sessionC []byte
		)
		if err := rows.Scan(&uid, &name, &config, &secretN, &secretC, &sessionN, &sessionC); err != nil {
			return fmt.Errorf("postgres auth: validate target scan: %w", err)
		}

		if _, err := i.openTarget(uid, name, string(config), secretN, secretC, sessionN, sessionC); err != nil {
			return fmt.Errorf("postgres auth: %w", err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres auth: validate targets rows: %w", err)
	}

	return nil
}

func (i *Identity) validateUsers(ctx context.Context, conn *pgxpool.Conn) error {
	rows, err := conn.Query(ctx,
		`SELECT id, access_key_id, prefix, secret_key_nonce, secret_key_ciphertext
		   FROM s3vault_users ORDER BY id`)
	if err != nil {
		return fmt.Errorf("postgres auth: validate users: %w", err)
	}
	defer rows.Close()

	type seen struct {
		key    string
		prefix string
	}

	var users []seen

	for rows.Next() {
		var (
			id         int64
			key        string
			prefix     string
			nonce      []byte
			ciphertext []byte
		)
		if err := rows.Scan(&id, &key, &prefix, &nonce, &ciphertext); err != nil {
			return fmt.Errorf("postgres auth: validate user scan: %w", err)
		}

		if key == "" {
			return fmt.Errorf("postgres auth: user %d has an empty access_key_id", id)
		}

		if !keying.IsCanonicalPrefix(prefix) {
			return fmt.Errorf("postgres auth: user %s has non-canonical prefix %q", key, prefix)
		}

		if _, err := secretbox.Open(i.masterKey, nonce, ciphertext, key); err != nil {
			return fmt.Errorf("postgres auth: user %s: %w", key, err)
		}

		for _, other := range users {
			if keying.PrefixesOverlap(prefix, other.prefix) {
				return fmt.Errorf("postgres auth: users %s and %s have overlapping prefixes %q and %q",
					other.key, key, other.prefix, prefix)
			}
		}

		users = append(users, seen{key: key, prefix: prefix})
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres auth: validate users rows: %w", err)
	}

	return nil
}

func (i *Identity) sealSecret(accessKeyID, secret string) (nonce, ciphertext []byte, err error) {
	return secretbox.Seal(i.masterKey, []byte(secret), accessKeyID)
}

func (i *Identity) openSecret(accessKeyID string, nonce, ciphertext []byte) (string, error) {
	plain, err := secretbox.Open(i.masterKey, nonce, ciphertext, accessKeyID)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}

// AAD domains separate the frontend secret (<access_key_id>) from target
// secrets, and the target secret from the target session token. Target secrets
// are bound to the target's immutable uid, so moving a ciphertext to another
// target row cannot decrypt, and renaming a target does not re-seal anything.
func targetSecretAAD(targetUID string) string {
	return "s3.secret_key:" + targetUID
}

func targetSessionAAD(targetUID string) string {
	return "s3.session_token:" + targetUID
}

func (i *Identity) sealTargetSecret(targetUID, secret string) (nonce, ciphertext []byte, err error) {
	return secretbox.Seal(i.masterKey, []byte(secret), targetSecretAAD(targetUID))
}

func (i *Identity) sealTargetSession(targetUID, token string) (nonce, ciphertext []byte, err error) {
	if token == "" {
		return nil, nil, nil
	}

	return secretbox.Seal(i.masterKey, []byte(token), targetSessionAAD(targetUID))
}

// openTarget assembles a target from its non-secret jsonb and the sealed
// columns. It validates the result, so a direct SQL edit that bypasses the CLI
// fails here instead of steering requests at a malformed destination.
func (i *Identity) openTarget(targetUID, targetName, raw string, secretNonce, secretCiphertext, sessionNonce, sessionCiphertext []byte) (port.S3Target, error) {
	t, err := s3target.DecodeStored([]byte(raw))
	if err != nil {
		return port.S3Target{}, err
	}

	if len(secretNonce) == 0 || len(secretCiphertext) == 0 {
		return port.S3Target{}, errors.New("target has no sealed secret_key")
	}

	secret, err := secretbox.Open(i.masterKey, secretNonce, secretCiphertext, targetSecretAAD(targetUID))
	if err != nil {
		return port.S3Target{}, fmt.Errorf("target %s: decrypt secret: %w", targetName, err)
	}

	t.SecretKey = string(secret)

	if len(sessionCiphertext) > 0 {
		token, err := secretbox.Open(i.masterKey, sessionNonce, sessionCiphertext, targetSessionAAD(targetUID))
		if err != nil {
			return port.S3Target{}, fmt.Errorf("target %s: decrypt session token: %w", targetName, err)
		}

		t.SessionToken = string(token)
	}

	if err := s3target.Validate(t); err != nil {
		return port.S3Target{}, fmt.Errorf("target %s: %w", targetName, err)
	}

	return t, nil
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	return errors.As(err, &pgErr) && pgErr.SQLState() == "23505"
}
