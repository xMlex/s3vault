# s3vault architecture

s3vault is a Go CLI and HTTP server that archives local files to S3-compatible object storage or a local directory, optionally encrypts them client-side, downloads and decrypts them, and serves plaintext over HTTP (optional persistent disk cache, off by default).

This document is the source of truth for component boundaries, object identity, encryption format, and security constraints. Implementation status is marked per section.

## Goals

- Production-small binary: stdlib first, few mature dependencies.
- Stream large files; do not `ReadAll` object bodies.
- Idempotent uploads via HEAD metadata, not ETag.
- Swappable object store, encryption, and cache backends behind small interfaces.
- Secrets never on the command line or in unstructured logs.

Local files are kept after a successful upload unless `--delete-after-upload` is set.
When the object already exists with identical plaintext (`skip`), use `--delete-if-exists`.

## Architecture choice

**Hexagonal-lite + manual constructor injection** (no Wire/Fx/do).

Two driving adapters (Cobra CLI and HTTP) share application services. Driven adapters implement ports: scanner, object store, encryptor, cache.

Rejected alternatives:

- Flat `cmd/`-only layout — hard to test server and S3 separately.
- Full Clean/DDD — no rich domain, only file pipelines.
- DI containers — fewer than ten services; wiring stays in constructors / CLI `RunE`.

```text
CLI (cobra) ──► ArchiveService ──► (optional) RemoteIngest HTTP PUT
             └► FetchService ──► HTTP GET/HEAD
                      │
         ┌────────────┼────────────┐
         ▼            ▼            ▼
      Scanner     ObjectStore   Encryptor
         │            │            │
      filesystem   S3 | local   native / command / none
                                   │
                              PlaintextCache (disk)

HTTP PUT /files ──► ArchiveService (same encrypt + Put as upload)
S3 API (SigV4) ──► same Fetch/Archive via S3Identity
```

Interfaces live in `internal/port` (multiple consumers). Adapters return concrete types. Compile-time checks: `var _ port.Scanner = (*scanner.FS)(nil)`.

`ObjectStore` includes `Head`/`Put`/`Get`/`GetRange`/`Delete`/`List`. Frontend S3 auth uses `port.S3Identity` (`Lookup`, `Allow`).

`backend.type` picks the `ObjectStore` adapter (`s3` or `local`); `cli.newObjectStore` is the only construction site and logs the resolved location once per run (`op=backend`: `dir` + `layout` for local, `bucket`/`endpoint` for S3). Everything above the port — services, HTTP, S3 facade, identity — is backend-agnostic. `internal/storetest.RunConformance` pins the shared contract for both adapters.

## Layout

| Path | Role |
| --- | --- |
| `cmd/s3vault` | `main`: signals, exit codes, version ldflags |
| `internal/cli` | Cobra command tree, Viper init, stdout/stderr |
| `internal/config` | Schema, defaults, validation |
| `internal/domain` | `FileInfo`, `ObjectMeta`, `ArchiveStats`, sentinels |
| `internal/port` | `Scanner`, `ObjectStore`, `Encryptor`, `PlaintextCache`, `RemoteIngest` |
| `internal/service` | Archive and Fetch orchestration |
| `internal/adapter/scanner` | Recursive walk, mtime filter, symlink policy |
| `internal/adapter/s3` | AWS SDK v2 client (AWS and MinIO) |
| `internal/adapter/local` | Local filesystem object store (`os.Root`, atomic Put) |
| `internal/adapter/encrypt` | Passthrough, native S3VLT01, external command |
| `internal/adapter/remote` | HTTP client for remote ingest (`PUT /files/...`) |
| `internal/adapter/cache` | Disk plaintext cache (`os.Root`, lockfile, LRU) |
| `internal/httpserver` | Loopback HTTP, Range via cached plaintext, PUT ingest |
| `internal/s3api` | Path-style S3 SigV4 facade (Get/Put/Delete/List + Head) over Fetch/Archive |
| `internal/adapter/s3auth` | Static `S3Identity` (access/secret → principal / Allow bucket) |
| `internal/metrics` | Prometheus collectors (files, bytes, transfer histograms, cache, HTTP, S3) |
| `internal/keying` | Local path → object key |
| `internal/period` | `7d` / `24h` / `1w` parser |
| `internal/identity` | Skip / overwrite / fail from HEAD metadata or S3VCTR01 Range |
| `internal/container` | Fixed S3VCTR01 object envelope (identity in body) |
| `internal/hash` | Streaming SHA-256 of local files |
| `internal/port/cache.go` | Cache port |
| `internal/storetest` | Shared `ObjectStore` contract checks (local + S3) |

There is no `pkg/`. `internal/app` is reserved if composition outgrows `internal/cli`.

## Ports

```go
type Scanner interface {
    Scan(ctx context.Context, root string, olderThan time.Duration) iter.Seq2[domain.FileInfo, error]
}

type ObjectStore interface {
    Head(ctx context.Context, key string) (domain.ObjectMeta, error) // missing → Exists=false
    Put(ctx context.Context, key string, r io.Reader, meta domain.PutMeta) error
    Get(ctx context.Context, key string) (io.ReadCloser, domain.ObjectMeta, error)
    GetRange(ctx context.Context, key string, start, end int64) (io.ReadCloser, domain.ObjectMeta, error)
    Delete(ctx context.Context, key string) error
    List(ctx context.Context, opts domain.ListOptions) (domain.ListPage, error)
}

type Encryptor interface {
    Encrypt(ctx context.Context, dst io.Writer, src io.Reader) error
    Decrypt(ctx context.Context, dst io.Writer, src io.Reader) error
}

type PlaintextCache interface {
    Get(ctx context.Context, id CacheID) (path string, hit bool, err error)
    Lookup(ctx context.Context, id CacheID) (path string, meta EntryMeta, hit bool, err error)
    Populate(ctx context.Context, id CacheID, meta EntryMeta, fill func(w io.Writer) error) (path string, err error)
    MarkValidated(ctx context.Context, id CacheID, meta EntryMeta) error
}
```

## CLI

```text
s3vault archive <dir> [--older-than 7d] [--dry-run] [--workers N] [--fail-fast]
                      [--delete-after-upload] [--delete-if-exists] [--prefix] [--bucket]
                      [--metrics-listen]
s3vault upload <file> [--key rel] [--root dir] [--dry-run]
                      [--delete-after-upload] [--delete-if-exists]
                      [--prefix] [--bucket] [--metrics-listen]
s3vault download <object-key> [dest] [--metrics-listen]  # dest omitted or "-" → stdout
s3vault server [--listen] [--metrics-listen]
s3vault cache stats|clear
s3vault version
```

`upload` uses the same HEAD identity and encryptor as `archive`. There is no mtime filter. The default object key is `prefix` plus the filename (`--root` defaults to the file’s parent directory). `--key` is relative to `s3.prefix` (same rules as HTTP `/files/{path...}`).

Rules: `RunE`, `SilenceUsage` / `SilenceErrors`, logs JSON on stderr, summaries on stdout, version via `-X main.version`.

Exit codes: `0` success; `1` runtime / partial file failures; `2` usage (Cobra); `130` SIGINT from the shell.

## Configuration

Precedence (Viper): flags > env `S3VAULT_*` (`.` and `-` → `_`) > YAML file > defaults.
Env keys without a YAML entry or default are registered via `config.BindEnv` so `Unmarshal` sees them (Viper `AutomaticEnv` alone is not enough).

Search path: `--config`, then `./s3vault.yaml`, then `$XDG_CONFIG_HOME/s3vault/s3vault.yaml`. Missing file is not an error.

Secrets belong in env (`S3VAULT_S3_SECRET_KEY`, AWS SDK chain) or `0600` key files. If `s3.secret_key` or `server.token` appear in the YAML, log a warning unless `s3.allow_secrets_in_config: true`.

Backend: `backend.type` is `s3` (default) or `local`; `local` requires `backend.local.dir`, resolved to an absolute path in `Normalize`. `backend.local.layout` is `container` (default) or `raw`; `raw` requires `encryption.mode=none`.

S3: endpoint, region, bucket, prefix, access/secret/session, TLS, path-style. Empty endpoint uses AWS defaults; non-empty endpoint targets MinIO and other S3-compatible APIs.

The object key prefix stays in `s3.prefix` for both backends (`--prefix`, `S3VAULT_S3_PREFIX` and remote clients already use it); read it through `Config.KeyPrefix()`. `Config.CacheNamespace()` is the per-backend cache namespace: the bucket for S3, `local:<dir>` for the local store.

## Local filesystem backend

`internal/adapter/local` stores each object as one file under `backend.local.dir`.

- **`layout: container` (default):** each file holds exactly the bytes S3 would hold (`S3VCTR01` container plus payload), so identity, dedup, encryption and the S3 facade behave the same.
- **`layout: raw`:** plaintext is stored as-is (no `S3VCTR01` prefix). Identity lives in an adjacent sidecar `*.s3vault-meta` (exact 128-byte `S3VCTR01` header). Requires `encryption.mode=none` (config rejects otherwise). `Head`/`Get` expose sidecar fields so `identity.ResolveRemote` can skip/dedup without Range magic. Sidecars are never listed; keys ending in `.s3vault-meta` are reserved. `Delete` removes the object first, then the sidecar (so a failed object remove cannot leave plaintext without identity).

- Access goes through `os.Root`; keys must survive `path.Clean` unchanged and be `filepath.IsLocal`, otherwise `domain.ErrInvalidPath`. `.s3vault-tmp/` is reserved and never listed.
- The directory is created `0700` when missing (an existing directory keeps its mode); object files are `0600`.
- `Put` streams into a temp file in `.s3vault-tmp/`, then `Sync` + `rename`; interrupted writes are dropped when the store is opened. Parent directories are created `0700`. Raw layout also writes the sidecar via the same temp/rename path after stripping an incoming EncNone container.
- `Head` reports `Exists=false` for a missing key (and for a path whose parent is a regular file); `Get`/`GetRange` return `domain.ErrNotFound`.
- `Delete` succeeds on a missing key and prunes directories it leaves empty.
- Deliberate differences from S3: `ETag` is synthetic (size + mtime, quoted) and only feeds cache revalidation — content identity still comes from the container header or raw sidecar; a range starting past the last byte yields an empty body instead of `416`; a key cannot be both a file and a directory (S3 allows `a` and `a/b`); `List` walks and sorts the whole tree under the prefix, so it is linear in object count.

## Scanner and symlinks

- Recurse from `archive <dir>`; emit only regular files.
- Include file iff `mtime < now - older-than` (strictly older).
- Directories are never uploaded.
- **Default: do not follow symlinks** (skip + warn). `--follow-symlinks` / `archive.follow_symlinks`: follow only if `EvalSymlinks` stays under the scan root; otherwise fail with `ErrSymlinkEscape`. The stored object key uses the symlink’s relative path; content is read from the target.

## Object keys

`keying.Mapper` is deterministic and shared by upload and download:

1. `filepath.Abs` on root and file.
2. `filepath.Rel`; reject anything that is not `filepath.IsLocal`.
3. `filepath.ToSlash` so keys never contain `\`.
4. Join trimmed `s3.prefix` with `path.Join` (always `/`).

Example: root `/data/app`, file `/data/app/logs/2026/application.log`, prefix `backups` → `backups/logs/2026/application.log`.

## Object identity (dedup)

Do **not** use S3 ETag as content identity (multipart ETag is not MD5 of the body).

Every uploaded object begins with a fixed **S3VCTR01** container header (128 bytes) that embeds plaintext identity, encryption mode, wrap, and command provider. Identity does **not** use S3 user-metadata on new Puts (Range GET of the header is required). Legacy objects that still carry `s3vault-*` metadata remain readable as a fallback when the body is not a container.

Before Put:

1. Stream local plaintext SHA-256 (`internal/hash`).
2. Resolve remote identity (`internal/identity.ResolveRemote`):
   - `HeadObject` for existence / ETag / LastModified (and any identity already on Head: legacy user-metadata or local raw sidecar).
   - `GetRange` bytes `0-127`, parse S3VCTR01 (CRC-checked).
   - If not a container (or peek is corrupt while Head already has SHA-256): keep Head identity.
3. Compare identity fields:

| Source | Meaning |
| --- | --- |
| header SHA-256 | Raw SHA-256 of **plaintext** |
| plaintext_size | Plaintext size |
| source_mtime | Source mtime (informational, not used for skip) |
| enc | `none` / `native` / `command` |
| wrap | `rsa-oaep` / `keyfile` / empty (native DEK wrap) |
| provider | Command provider name (e.g. `cryptopro`), empty otherwise |
| thumbprint | SHA-1 of CryptoPro recipient cert (`command` mode); used on decrypt |

Decision (`internal/identity.Decide`):

- No object → upload.
- Remote SHA-256 equals local (and size matches if present) → **skip** (identical).
- Otherwise `archive.on_change`: `overwrite` (default) / `skip` (omit upload; local kept) / `fail`.
- `--delete-after-upload`: remove local file after a new upload succeeds.
- `--delete-if-exists`: remove local file on identical skip only (not on on_change=skip omit).

Changing encryption keys without changing file content does not re-upload (same plaintext hash). Re-encrypt is a future explicit command. For CryptoPro, inventory and decrypt of older objects prefer thumbprint from S3VCTR01 header, then legacy `s3vault-cryptopro-thumbprint` metadata, then `encryption.command.thumbprint` / encrypt argv.

The S3 backend must support HTTP Range GETs for identity checks.

## Object container `S3VCTR01`

Detection by magic bytes (not file extension). Layout (big-endian), fixed **128** bytes:

```text
0..7    "S3VCTR01"
8       version u8 = 1
9       flags u8
10..11  header_total u16 BE = 128
12..19  plaintext_size u64 BE
20..51  sha256 32 raw bytes
52      enc u8 (0=none 1=native 2=command)
53      wrap u8 (0=n/a 1=RSA-OAEP-256 2=KEK-AES-GCM)
54      tp_len u8 (0 or 20)
55      provider_len u8 (0..32)
56..75  thumbprint 20 bytes (zero-padded if unused)
76..83  source_mtime i64 BE unix (0 = unknown)
84..115 provider 32 bytes ASCII (zero-padded; e.g. "cryptopro")
116..123 reserved zeros
124..127 crc32 IEEE of bytes[0..123]
128..   opaque payload (plaintext | S3VLT01 stream | command ciphertext)
```

Upload writes header then streams encrypt/copy into Put (`io.MultiReader`). Download unwraps before `DecryptAuto`. Native objects are `S3VCTR01 || S3VLT01 || chunks`. Legacy objects without the container remain readable via legacy metadata / existing decrypt paths.

## Encryption

RSA never encrypts file bytes. Envelope only:

1. Random 32-byte DEK (`crypto/rand`).
2. AES-256-GCM in chunks (default 64 KiB plaintext).
3. Wrap DEK: RSA-OAEP SHA-256, or AES-GCM with a KEK from `key_file` (32 raw bytes or SHA-256 of the file).

Modes: `none` (copy), `native` (S3VLT01 inside S3VCTR01), `command` (`exec.CommandContext`, argv from config, no shell, stderr capped at 64 KiB, timeout, secrets only via env not argv). Native wrap (`rsa-oaep` / `keyfile`) and command `provider` (default `cryptopro`) are written into the container header. CryptoPro recipient thumbprint is written to the container header on Put; download/server set `CRYPTOPRO_THUMBPRINT` from header first, then legacy metadata, then config when running the decrypt command.

### Format `S3VLT01`

Detection is by magic bytes, not file extension.

```text
8 bytes  "S3VLT01\n"
uint32 BE header_len
JSON header:
  v, alg=AES-256-GCM-CHUNK, chunk, nonce_prefix (8 bytes),
  wrap=RSA-OAEP-256|KEK-AES-GCM, wrapped_dek, wrap_nonce (KEK only)
repeated:
  uint32 BE ciphertext_len (includes 16-byte GCM tag)
  ciphertext
```

Per-chunk nonce = `nonce_prefix || uint32BE(index)` (12 bytes). Unknown `v`/`alg` fails closed.

Download: peek magic → native/command decrypt, else copy as plaintext. Command mode always runs the decrypt argv.

HTTP materialize uses the same `DecryptAuto` path into the disk cache.

## Archive concurrency and reliability

- `errgroup.SetLimit(workers)`; one file error does not cancel siblings unless `--fail-fast`.
- Upload: `io.Pipe` from encrypt goroutine into S3 manager uploader (multipart). Context cancel aborts the SDK call.
- Success only after Put returns. Temp/partial local dest files are removed on download error; dest is written via temp + `fsync` + `rename`.
- SDK standard retry/backoff on S3.

Summary fields: `found`, `uploaded`, `skipped`, `failed`, `bytes_uploaded`, `duration`. Dry-run increments `found` only (no store calls).

## Download

Implemented: `Get` → `DecryptAuto` → file or stdout. HTTP/S3 Get/Head: `Fetch.Materialize` then `http.ServeContent` (Range on seekable plaintext). Stdout downloads are never cached.

## Cache

`cache.enabled` (default **false**, env `S3VAULT_CACHE_ENABLED`) gates the persistent plaintext disk cache. When disabled, each HTTP/S3 Get/Head decrypts into an ephemeral temp file (`0600`), serves via `ServeContent`, then deletes it — no soft-TTL staleness, no leftover plaintext after the response. CLI `download` is unchanged (never used the disk cache).

When **enabled**, store **decrypted** files on disk:

- Cache id = SHA-256(`Config.CacheNamespace()`, object key, enc fingerprint), so S3 and local entries never collide. Object version (ETag / plaintext SHA-256) is stored in the sidecar, not in the id.
- Paths: `cache/ab/<hex>` plus sidecar meta (TTL, size, etag, sha256, `validated_at`). Hex-only names; open via `os.Root`.
- Files `0600`, dirs `0700`.
- `Populate`: `singleflight` in-process + lockfile across processes; write `*.tmp` → fsync → rename. Identity change for the same id rewrites plaintext.
- Sidecar `.meta`: unique `*.tmp` → rename (atomic); concurrent Get atime bumps must not tear JSON.
- Hard TTL (`cache.ttl`, default 168h) + max bytes LRU (atime in meta). Get rewrites atime at most once per minute (not every hit). Expired entries are also dropped lazily on Get/Lookup.
- Soft TTL (`cache.soft_ttl`, default **20s**): within the window a Materialize hit needs **no S3** call. After soft TTL, the stale entry is served immediately and runs HEAD in the background; unchanged SHA-256/ETag only bumps `validated_at`, changed identity re-Populates. `soft_ttl: 0` forces a synchronous HEAD on every request.
- Background sweeper (`cache.sweep_interval`, default **15m**, `0` = off): on `s3vault server`, periodically removes hard-TTL expired entries so unused objects do not linger until LRU pressure. First sweep runs at start.
- In-memory index (loaded at open, updated on Populate/Get/remove/Clear): O(1) `Usage`, in-memory LRU eviction, Get hits without re-reading JSON. Index miss still falls back to disk (other processes).
- Corrupt meta → drop entry and miss (re-Populate).
- Stampede: one download per id+identity; waiters use the same result.

**Risk (when enabled):** plaintext on disk. Mitigations: loopback server bind, `0700` cache dir, short TTL, optional tmpfs, `cache clear`. Soft TTL trades up to `soft_ttl` of possible staleness for fewer backend HEADs. Leave `cache.enabled: false` unless you need hit latency / fewer backend Gets.

## HTTP server

Listen `127.0.0.1:8080` by default. Empty bearer token + non-loopback listen → refuse to start unless S3 frontend credentials are set (multiplexed S3 API); `server.s3_listen` without those credentials is refused too. Both checks are backend-independent and name the offending address plus the config keys and env vars that fix them (`ErrTokenRequired`, `ErrS3CredsRequired` in `internal/httpserver/bind.go`).

- `GET`/`HEAD /files/{path...}` — same keying as upload; max path 2048.
- `PUT /files/{path...}` — ingest plaintext: spool temp (`0600`) while hashing SHA-256 → same Archive identity/encrypt/Put as CLI `upload` (precomputed hash, no second hash pass). Status: `201` uploaded, `200` identical skip, `204` policy omit (`on_change=skip` with different content), `409` on_change=fail conflict. Optional header `X-S3Vault-Mtime` (RFC3339). Requires Archive wired into the server (always on `s3vault server`).
- `GET /health`, `GET /ready` (cheap S3 check).
- Metrics on a **separate** `metrics_listen` (`/metrics`).
- Serve via `http.ServeContent` after `Materialize` → Range, `Content-Length`, `Last-Modified`, `ETag`.
- With `cache.enabled`: first miss fully decrypts into the disk cache; soft-TTL / SWR as above. With cache disabled: ephemeral temp per request (still seekable for Range). Seekable ciphertext decrypt without spooling is a follow-up (chunk index already supports it).

Graceful `Shutdown` on SIGTERM.

### S3 API gateway (SigV4 plaintext facade)

Optional path-style S3 API for standard clients (`aws-cli`, SDKs). Enabled when `server.s3_access_key` and `server.s3_secret_key` are set (prefer env `S3VAULT_SERVER_S3_*`).

- **Semantics:** same as `/files` — Put encrypts into backend; Get/Head via `Fetch.Materialize` (disk cache + soft-TTL / SWR when `cache.enabled`, else ephemeral decrypt). Works over either backend; with `backend.type: local` and no bucket configured the facade advertises `s3vault`.
- **Auth:** AWS SigV4 via `amwolff/awsig`; credentials resolved through `port.S3Identity` (`Lookup` + `Allow`). v1 adapter is static single principal + one virtual bucket (`server.s3_bucket`, default `s3.bucket`). Optional `server.s3_bucket_as_prefix`: any client bucket is allowed and prepended to the object key under backend `s3.bucket` / `s3.prefix` (`s3://reports/a.log` → `{prefix}/reports/a.log`). Future: multi-key / bucket bindings without changing handlers.
- **Listen:** `server.s3_listen` empty → multiplex on `server.listen` (reserved first segments `health`, `ready`, `files` stay on HTTP Bearer API). Non-empty → dedicated listener (+ `/health` without auth).
- **Ops:** GetObject, PutObject, DeleteObject, ListObjectsV2, HeadObject, HeadBucket, ListBuckets. No multipart / CreateBucket / virtual-host in v1.
- **Checksum:** Get/Head/Put responses include `x-amz-checksum-sha256` (base64 of plaintext SHA-256) and `x-amz-checksum-type: FULL_OBJECT` when identity is known. Client request checksum headers are ignored in v1.
- **Metrics:** existing HTTP instrumentation plus `s3vault_s3_requests_total{op,result}` (low cardinality).
- Frontend S3 keys are **not** backend `s3.access_key`.

### Remote archive client

Hosts without CryptoPro/S3 credentials set `remote.url` (`S3VAULT_REMOTE_URL`) and reuse `S3VAULT_SERVER_TOKEN`. Then `archive` / `upload` PUT plaintext to that server (server encrypts and stores). Optional `remote.rate_limit_bps` caps aggregate upload bandwidth across workers. The client includes its `s3.prefix` / `--prefix` in the PUT path (`/files/{prefix}/...`); the server may add its own `s3.prefix` as a common root (leave server prefix empty when each job supplies its own prefix, e.g. `fs.auto-sopd`).

## Logging and metrics

`log/slog` JSON on stderr: `time`, `level`, `msg`, `op`, path/key, size, duration, `err`. Levels debug/info/warn/error. Never log credentials, PEM, or file bodies.

Prometheus (low cardinality — no full path labels) on `metrics_listen` (server) or `--metrics-listen` (one-shot CLI):

- `s3vault_files_total{op,result}` — found / uploaded / skipped / failed / downloaded
- `s3vault_bytes_total{direction}` — plaintext bytes in (`download`) and out (`upload`)
- `s3vault_upload_duration_seconds`, `s3vault_upload_size_bytes`
- `s3vault_download_duration_seconds`, `s3vault_download_size_bytes` (S3 Get+decrypt, not cache hits)
- `s3vault_cache_hits_total`, `s3vault_cache_misses_total`, `s3vault_cache_entries`, `s3vault_cache_bytes`
- `s3vault_http_request_duration_seconds`, `s3vault_http_requests_total`, `s3vault_http_requests_in_flight`, `s3vault_http_response_size_bytes` (`code`, `method` only)
- `s3vault_s3_requests_total{op,result}` — S3 API ops (`get`, `put`, `delete`, `list`, `head`, …)
- Go/process collectors on `s3vault server`

## Security constraints

- Path traversal: `filepath.IsLocal` on relative paths; HTTP must use the same mapper.
- No `bash -c`; command encrypt argv is a string slice.
- TLS verify on by default.
- Cache and dest files `0600`.
- Private keys and KEKs only from files/env, mode `0600`.

## Dependencies (why)

| Library | Why | Not chosen |
| --- | --- | --- |
| aws-sdk-go-v2 + s3 + manager | Retry, multipart, custom endpoint | minio-go |
| amwolff/awsig | Server-side SigV4 for S3 API facade (UNSIGNED-PAYLOAD / streaming) | hand-roll; SeaweedFS/MinIO server packages; gofakes3 |
| cobra + viper | Subcommands + layered config | urfave/cli, koanf |
| log/slog | Stdlib structured logs | zap/zerolog |
| prometheus/client_golang | HTTP, cache, archive/upload/download metrics | — |
| golang.org/x/sync | errgroup, singleflight | hand-rolled pools |
| stdlib crypto | AES-GCM, RSA-OAEP | age (poor Range story) |
| testify | Tests | — |

Disk cache is custom (samber/hot is in-memory). Retry-go is unused; SDK retries S3.

## Tests

Unit (present): period parser, keying, identity, scanner, native/command encrypt, config, archive skip, single-file upload, fetch download, disk cache, HTTP Range/auth, Prometheus collectors, local backend (contract, keys, ranges, list) and a CLI upload/download roundtrip over the local backend.

Integration (planned, `//go:build integration`): MinIO — upload, skip, change, encrypt roundtrip, command encrypt, cache stampede, corrupt object, S3 down, interrupted download, graceful shutdown.

CI (planned): `go test -race`, golangci-lint, gosec, govulncheck.

## Status

| Area | Status |
| --- | --- |
| CLI skeleton, config, slog | Done |
| Scanner, keying, archive dry-run | Done |
| S3 Head/Put/Get, identity, workers | Done |
| Native + command encryption, download | Done |
| Disk cache, HTTP, Prometheus HTTP/cache metrics | Done |
| Archive/upload/download Prometheus metrics | Done |
| `server` / `cache` commands | Done |
| `upload` command | Done |
| Remote ingest (`PUT /files`, `remote.url`) | Done |
| S3 API gateway (SigV4, Get/Put/Delete/ListV2 + Head) | Done |
| Local filesystem backend (`backend.type: local`) | Done |
| Docker, MinIO tests, CI | Not started |
