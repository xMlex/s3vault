CREATE TABLE s3vault_encryption_profiles (
    uid        text        PRIMARY KEY,
    name       text        NOT NULL,
    config     jsonb       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT s3vault_encryption_profiles_name_key UNIQUE (name),
    CONSTRAINT s3vault_encryption_profiles_uid_len
        CHECK (octet_length(uid) = 32),
    CONSTRAINT s3vault_encryption_profiles_name_nonempty
        CHECK (name <> ''),
    CONSTRAINT s3vault_encryption_profiles_config_object
        CHECK (jsonb_typeof(config) = 'object')
);

CREATE TABLE s3vault_targets (
    uid                text        PRIMARY KEY,
    name               text        NOT NULL,
    config             jsonb       NOT NULL,
    secret_nonce       bytea       NOT NULL,
    secret_ciphertext  bytea       NOT NULL,
    session_nonce      bytea,
    session_ciphertext bytea,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT s3vault_targets_name_key UNIQUE (name),
    CONSTRAINT s3vault_targets_uid_len
        CHECK (octet_length(uid) = 32),
    CONSTRAINT s3vault_targets_name_nonempty
        CHECK (name <> ''),
    CONSTRAINT s3vault_targets_config_object
        CHECK (jsonb_typeof(config) = 'object'),
    CONSTRAINT s3vault_targets_config_no_plaintext_secret
        CHECK (NOT (config ? 'secret_key') AND NOT (config ? 'session_token')),
    CONSTRAINT s3vault_targets_secret_nonce_len
        CHECK (octet_length(secret_nonce) = 12),
    CONSTRAINT s3vault_targets_secret_ciphertext_len
        CHECK (octet_length(secret_ciphertext) > 16),
    CONSTRAINT s3vault_targets_session_pair
        CHECK ((session_nonce IS NULL) = (session_ciphertext IS NULL)),
    CONSTRAINT s3vault_targets_session_nonce_len
        CHECK (session_nonce IS NULL OR octet_length(session_nonce) = 12),
    CONSTRAINT s3vault_targets_session_ciphertext_len
        CHECK (session_ciphertext IS NULL OR octet_length(session_ciphertext) > 16)
);

CREATE TABLE s3vault_users (
    id                     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                   text        NOT NULL,
    access_key_id          text        NOT NULL,
    secret_key_nonce       bytea       NOT NULL,
    secret_key_ciphertext  bytea       NOT NULL,
    prefix                 text        NOT NULL,
    encryption_profile_uid text,
    s3_target_uid          text,
    enabled                boolean     NOT NULL DEFAULT true,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT s3vault_users_name_key UNIQUE (name),
    CONSTRAINT s3vault_users_access_key_key UNIQUE (access_key_id),
    CONSTRAINT s3vault_users_prefix_key UNIQUE (prefix),
    CONSTRAINT s3vault_users_access_key_nonempty
        CHECK (access_key_id <> ''),
    CONSTRAINT s3vault_users_prefix_nonempty
        CHECK (prefix <> ''),
    CONSTRAINT s3vault_users_nonce_len
        CHECK (octet_length(secret_key_nonce) = 12),
    CONSTRAINT s3vault_users_ciphertext_len
        CHECK (octet_length(secret_key_ciphertext) > 16),
    CONSTRAINT s3vault_users_encryption_profile_fkey
        FOREIGN KEY (encryption_profile_uid)
        REFERENCES s3vault_encryption_profiles(uid) ON DELETE RESTRICT,
    CONSTRAINT s3vault_users_s3_target_fkey
        FOREIGN KEY (s3_target_uid)
        REFERENCES s3vault_targets(uid) ON DELETE RESTRICT
);

CREATE INDEX s3vault_users_encryption_profile_idx
    ON s3vault_users (encryption_profile_uid);
CREATE INDEX s3vault_users_s3_target_idx
    ON s3vault_users (s3_target_uid);
