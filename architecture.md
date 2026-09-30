# s3vault architecture

s3vault is a Go CLI and HTTP server that archives local files to S3-compatible object storage or a local directory, optionally encrypts them client-side, downloads and decrypts them, and serves plaintext over HTTP (optional persistent disk cache, off by default).

This document is the source of truth for component boundaries, object identity, encryption format, and security constraints. Implementation status is marked per section.

Known gaps between this document and the code are tracked separately in [problems.md](problems.md); open design questions about the encrypt/decrypt layer are in [docs/decrypt-detection.md](docs/decrypt-detection.md).

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

Two driving adapters (Cobra CLI and the gateway's S3 facade) share application services. Driven adapters implement ports: scanner, object store, encryptor, cache.

Rejected alternatives:

- Flat `cmd/`-only layout — hard to test server and S3 separately.
- Full Clean/DDD — no rich domain, only file pipelines.
- DI containers — fewer than ten services; wiring stays in constructors / CLI `RunE`.

```text
CLI (cobra) ──► ArchiveService ──► ObjectStore (S3 protocol to the gateway or storage)
             └► FetchService   ──► ObjectStore
                      │
         ┌────────────┼────────────┐
         ▼            ▼            ▼
      Scanner     ObjectStore   Encryptor
         │            │            │
      filesystem   S3 | local   native / command / none
                                   │
                              PlaintextCache (disk)

S3 API (SigV4) ──► same Archive/Fetch via S3Identity
HTTP /health /ready ──► probes only
```

Interfaces live in `internal/port` (multiple consumers). Adapters return concrete types. Compile-time checks: `var _ port.Scanner = (*scanner.FS)(nil)`.

`ObjectStore` includes `Head`/`Put`/`Get`/`GetRange`/`Delete`/`List`. Frontend S3 auth uses `port.S3Identity` (`Lookup`, `Allow`).

`backend.type` picks the `ObjectStore` adapter (`s3` or `local`); `cli.newObjectStore` is the only construction site and logs the resolved location once per run (`op=backend`: `dir` for local, `bucket`/`endpoint` for S3). Everything above the port — services, HTTP, S3 facade, identity — is backend-agnostic. `internal/storetest.RunConformance` pins the shared contract for both adapters.

## Roles and topology

Every s3vault process occupies exactly one role, and the role is fixed by the command — never by a config key. There is no `role:` / `mode:` setting to keep in sync, for the same reason there is no `s3.tls`.

- **Storage** — where objects live. `backend.type: s3` (AWS, MinIO, any S3-compatible API) or `local` (a directory). The only place bytes are persisted.
- **Client** — an s3vault process that reads from or writes to the storage: `archive`, `upload`, `download`. It has no storage of its own.
- **Gateway** — `s3vault server`. It has **no storage of its own either**: it stands in front of the storage, serves plaintext, and is at the same time a **client of that storage**. One `ObjectStore` from `newObjectStore` (`internal/cli/root.go`) serves its reads and the S3 facade's Put / List / Delete.

The disambiguation this section exists for: **"server" in the command name means gateway, not storage.** A third-party S3 server is called *storage* throughout this document. A role is never called a "mode" — `mode` is reserved for `encryption.mode`.

A gateway exposes exactly one data frontend: the **S3 facade** (SigV4, `internal/s3api`). Its plain HTTP listener carries only `/health` and `/ready`. The former bearer `HTTP /files` frontend (`GET`/`HEAD`/`PUT`) and the `remote.url` ingest mode were removed; the gateway and its clients now speak one protocol, S3.

```text
origin — files on disk
   │
   │  scan / read
   ▼
client: archive | upload                     client: download
   │                                              │
   └────────── S3 protocol ──────────► gateway ──► storage
        (or straight to storage       (s3vault server; itself a client
         when s3.endpoint is           of the storage, reads and writes it)
         the real S3)
```

### Which config keys each role reads

`newObjectStore` (`internal/cli/root.go`) builds the storage backend for every role; there is no `Remote` config. A client that must go through a gateway sets `s3.endpoint` to the gateway's **S3 facade** and uses the gateway's `server.s3_access_key`/`server.s3_secret_key` as its own S3 credentials (path-style). There is no separate ingest channel, no `server.token`, and no write-only mode.

| command | role | storage | `s3.*` | `cache.*` | `server.s3_*` |
| --- | --- | --- | --- | --- | --- |
| `archive`, `upload` | client, write | direct — or via a gateway's S3 facade when `s3.endpoint` points at it | yes | no | no |
| `download` | client, read | same endpoint as write | yes | never used | no |
| `server` | gateway, and a client of the storage | direct | yes (backend) | yes | its own frontend |
| `cache stats`, `cache clear` | neither | no | ignored | local dir only | no |

Two unrelated key pairs live in one config schema, and mixing them is a misconfiguration in its own right. `server.s3_access_key`/`server.s3_secret_key` are the process's own frontend — `s3auth.Static` accepts that `accessKeyID` and nothing else — while `s3.access_key`/`s3.secret_key` are the credentials the process presents to its storage. On a client → gateway → storage path the client's `s3.access_key` *is* the gateway's `server.s3_access_key`, and the gateway's own `s3.access_key` is the storage's. Nothing enforces that the two differ: one pair in both slots works, and in a chain of gateways it means the outer gateway also holds the inner storage's credentials. The rule extends along the chain — each process's `s3.*` is the next hop's `server.s3_*`.

### Two consequences of that topology

**Layer count = the number of s3vault processes that framed the bytes.** A process frames when it encrypts, and the gateway frames even when it does not (see [Object shape](#object-shape)). A non-s3vault S3 client is transparent: `aws s3 cp` into a gateway yields one layer, the gateway's. An s3vault client with `mode=none` writing straight to the storage yields **no** layer — its object is the bare payload, readable as an ordinary file. An s3vault client with `mode=none` writing *through* a gateway yields one layer, the gateway's; with `mode=native`/`command`, two — the gateway's outer, the client's inner. Wherever this document says "two nested layers", read it as "a gateway is on the path and the client encrypts".

**A read strips exactly one layer.** `unwrapForDecrypt` calls `container.Unwrap` once (`internal/service/fetch.go`) and `DecryptAuto` undoes at most one payload encryption, so a process always returns one layer fewer than it found. An object is plaintext to a single process only when it holds exactly one layer — meaning the writer wrote straight into the storage that the reader reads. If a gateway is on the write path it must also be on the read path: two layers are removed by two processes, in order, never by one process twice.

Because a client that goes through a gateway points **both** `s3.endpoint` (write and read) at the same gateway, the arithmetic is symmetric: the gateway strips its layer on Get and the client strips its own on `download`. This is why the read path works with no special code — it is the ordinary client path with a different endpoint. Encryption on top is the client's own layer; a gateway `mode` is a second layer, and symmetric `mode` across the two sides is a configuration invariant, not something the format enforces.

## Layout

| Path | Component |
| --- | --- |
| `cmd/s3vault` | `main`: signals, exit codes, version ldflags |
| `internal/cli` | Cobra command tree, Viper init, stdout/stderr |
| `internal/config` | Schema, defaults, validation |
| `internal/domain` | `FileInfo`, `ObjectMeta`, `ArchiveStats`, sentinels |
| `internal/port` | `Scanner`, `ObjectStore`, `Encryptor`, `PlaintextCache`, `S3Identity` |
| `internal/service` | Archive and Fetch orchestration |
| `internal/adapter/scanner` | Recursive walk, mtime filter, symlink policy |
| `internal/adapter/s3` | AWS SDK v2 client (AWS and MinIO) |
| `internal/adapter/local` | Local filesystem object store (`os.Root`, atomic Put) |
| `internal/adapter/encrypt` | Passthrough, native S3VLT01, external command |
| `internal/adapter/cache` | Disk plaintext cache (`os.Root`, lockfile, LRU) |
| `internal/httpserver` | Plain HTTP `/health` + `/ready`, S3 facade dispatch |
| `internal/s3api` | Path-style S3 SigV4 facade (Get/Put/Delete/List + Head + multipart) over Fetch/Archive |
| `internal/s3api/s3err` | S3 wire-error codes and `WriteError` responses |
| `internal/adapter/s3auth` | Static `S3Identity` (access/secret → principal / Allow bucket) |
| `internal/metrics` | Prometheus collectors (files, bytes, transfer histograms, cache, HTTP, S3) |
| `internal/keying` | Local path → object key |
| `internal/period` | `7d` / `24h` / `1w` parser |
| `internal/identity` | Skip / overwrite / fail from HEAD metadata or S3VCTR01 Range |
| `internal/container` | Fixed S3VCTR01 object envelope (identity in body) |
| `internal/hash` | Streaming SHA-256 of local files |
| `internal/storetest` | Shared `ObjectStore` contract checks (local + S3) |
| `internal/s3test` | S3 config from repo `.env`/process env for integration tests |
| `internal/integration` | `//go:build integration` end-to-end tests against live S3/MinIO |

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
    Remove(ctx context.Context, id CacheID) error // best-effort drop after DeleteObject
}
```

`port` also defines `S3Identity` (`Lookup`, `Allow` — see [S3 API gateway](#s3-api-gateway-sigv4-plaintext-facade)) and the `CacheID` / `EntryMeta` / `Principal` / `S3Op` value types used in these signatures.

## CLI

```text
s3vault archive <dir> [--older-than 7d] [--dry-run] [--workers N] [--fail-fast]
                      [--delete-after-upload] [--delete-if-exists] [--prefix] [--bucket]
                      [--output text|json] [--metrics-listen]
s3vault upload <file> [--key rel] [--root dir] [--dry-run]
                      [--delete-after-upload] [--delete-if-exists]
                      [--prefix] [--bucket] [--output text|json] [--metrics-listen]
s3vault download <object-key> [dest] [--metrics-listen]  # dest omitted or "-" → stdout
s3vault server [--listen] [--s3-listen] [--metrics-listen]
s3vault cache stats|clear
s3vault version

# persistent on the root command
s3vault [--config file] [--log-level debug|info|warn|error] <command>
```

`upload` uses the same HEAD identity and encryptor as `archive`. There is no mtime filter. The default object key is `prefix` plus the filename (`--root` defaults to the file’s parent directory). `--key` is relative to `s3.prefix` (the same key rule the S3 facade uses).

Rules: `RunE`, `SilenceUsage` / `SilenceErrors`, `slog` text (`key=value`) on stderr, summaries on stdout, version via `-X main.version`.

Exit codes: `0` success; `1` any failure — usage errors (bad args, unknown flag), runtime errors, `ErrPartialFailures`, and interrupted runs. There is no separate usage or SIGINT code: `signal.NotifyContext` handles `SIGINT`/`SIGTERM` by cancelling the context, and the resulting `context.Canceled` exits `1`. `ExitError` exists so a command can request a code, but only `Code: 1` is ever constructed.

## Configuration

Precedence (Viper): flags > env `S3VAULT_*` (`.` and `-` → `_`) > YAML file > defaults.
All bindable keys are registered via `config.BindEnv` so `Unmarshal` sees them (Viper `AutomaticEnv` alone is not enough); `TestEnvKeysMatchConfigFields` keeps that list and the config structs in sync.

Exception to the precedence: `archive.fail_fast`, `archive.delete_after_upload` and `archive.delete_if_exists` are combined as `flag || config`. A `true` from env or YAML therefore cannot be turned back off by the CLI — there is no `--fail-fast=false` that reverts it.

Search path: `--config`, then `./s3vault.yaml`, `./s3vault.yml`, then the same two names under `$XDG_CONFIG_HOME/s3vault/` (or `$HOME/.config` when `XDG_CONFIG_HOME` is unset). The `.yml` variants exist so `SetConfigName` cannot pick up the `s3vault` binary. Not finding a file is not an error; an explicit `--config` that cannot be read **is** a hard error, while an auto-discovered file that fails to read only warns on stderr.

Secrets belong in env (`S3VAULT_S3_SECRET_KEY`, AWS SDK chain) or `0600` key files. If `s3.secret_key` or `server.s3_secret_key` appear in the YAML, log a warning unless `s3.allow_secrets_in_config: true`. The check uses `InConfig`, so env-supplied secrets are not flagged.

Backend: `backend.type` is `s3` (default) or `local`; `local` requires `backend.local.dir`, resolved to an absolute path in `Normalize`. The object shape is not a backend setting: `encryption.mode` alone decides it, on every backend — `none` writes the bare payload, `native`/`command` write the `S3VCTR01` container (see [Object shape](#object-shape)). The former `backend.local.layout` key is rejected at startup by `config.CheckRemovedKeys`.

Removed keys: `config.Load` calls `config.CheckRemovedKeys`, which fails startup if `remote.url`, `remote.rate_limit_bps`, or `server.token` is still present in the file or environment. Viper silently ignores unknown keys, so without this guard an upgrade would change behavior (or silently drop a token) without a word.

S3: endpoint, region, bucket, prefix, access/secret/session, path-style. Empty endpoint uses AWS defaults; non-empty endpoint targets MinIO and other S3-compatible APIs. There is no separate `s3.tls` key: the endpoint scheme is the single source of truth (`https://` verifies the certificate against the system store, `http://` disables TLS), so a boolean could only ever contradict the URL while appearing to work.

The object key prefix stays in `s3.prefix` for both backends (`--prefix`, `S3VAULT_S3_PREFIX`); read it through `Config.KeyPrefix()`. `Config.CacheNamespace()` is the per-backend cache namespace: the bucket for S3, `local:<dir>` for the local store.

## Local filesystem backend

`internal/adapter/local` stores each object as one file under `backend.local.dir`.

- The store keeps the bytes it is given, so a file holds exactly what an S3 backend would hold for the same `encryption.mode` and identity, dedup, encryption and the S3 facade behave the same on both. Whether those bytes carry the `S3VCTR01` container is the writer's decision, not the store's: an incoming container is kept whole, never stripped.
- An object with no container has no header to read a digest from, so the store exposes one as described under [Content identity](#content-identity). The config guard that used to police this combination is gone with `backend.local.layout`: `encryption.mode` alone decides the object shape, on every backend, so there is no combination left to reject.
- Access goes through `os.Root`; keys must survive `path.Clean` unchanged and be `filepath.IsLocal`, otherwise `domain.ErrInvalidPath`. `.s3vault-tmp/` is reserved and never listed.
- The directory is created `0700` when missing (an existing directory keeps its mode); object files are `0600`.
- `Put` streams into a temp file in `.s3vault-tmp/`, then `Sync` (file data) + `rename`; interrupted writes are dropped when the store is opened (`New` does `RemoveAll(.s3vault-tmp)` and fails if that cleanup fails). Parent directories are created `0700`. The `rename` is atomic for readers, but its durability is left to the filesystem: no directory `fsync` is issued, deliberately, for cross-platform simplicity (Windows and some network filesystems cannot fsync a directory anyway). The same applies to the disk cache's `rename`.
- `Put` stores the bytes unchanged and ignores `domain.PutMeta` except for the identity fields: a `PlaintextSHA256` in `PutMeta` is what tells the store the object has no container, so it records it for `Head`/`Get`. Nothing is persisted next to the object, and `ContentType` is not stored by this backend.
- `Head` reports `Exists=false` for a missing key (and for a path whose parent is a regular file); `Get`/`GetRange` return `domain.ErrNotFound`.
- `Delete` succeeds on a missing key and prunes directories it leaves empty.
- Deliberate differences from S3: the store's `ETag` is synthetic (size + mtime, quoted) but it is only a last-resort fallback — content identity is the plaintext SHA-256 parsed from the `S3VCTR01` header, or, for an object with no container, the SHA-256 of the stored bytes, so a same-size, same-mtime overwrite cannot masquerade as the old object; a range starting past the last byte yields an empty body instead of `416`; a key cannot be both a file and a directory (S3 allows `a` and `a/b`); `List` walks and sorts the whole tree under the prefix, so it is linear in object count.

## Scanner and symlinks

- Recurse from `archive <dir>`; emit only regular files.
- Include file iff `mtime < now - older-than` (strictly older).
- Directories are never uploaded.
- **Default: do not follow symlinks** (skip + warn). Opt in via `archive.follow_symlinks` (env `S3VAULT_ARCHIVE_FOLLOW_SYMLINKS`) only — there is no CLI flag for it: follow only if `EvalSymlinks` stays under the scan root; otherwise fail with `ErrSymlinkEscape`. The stored object key uses the symlink’s relative path; content is read from the target. A symlink resolving to a non-regular target is skipped with a distinct warning.

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
   - `HeadObject` for existence / ETag / LastModified (and any identity already on Head: legacy user-metadata).
   - `GetRange` bytes `0-127`, parse S3VCTR01 (CRC-checked).
   - If not a container (or peek is corrupt while Head already has SHA-256): keep Head identity.
   - For a containerless object the store exposes the digest it was given: `Put` records `PutMeta.PlaintextSHA256` under the object's `(path, size, mtime)` key, so an object this process wrote is never re-read to identify itself. Only objects left by an earlier process fall back to hashing the file, and even then a body counts as a container only if `container.Parse` accepts it, so a plaintext file that happens to start with the magic is hashed rather than misread. The digest is memoized in memory; the memo holds at most 4096 entries, evicting the least-recently-used, and is never persisted. `Archive` always hashes the local file, so `Decide` gets a real local digest for both object shapes and content-skip works either way.
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
- Remote SHA-256 equals local (and size matches if present) → **skip** (identical, nothing written).
- Otherwise → **upload** (overwrite). There is no write policy: `archive.on_change` was removed, because a single global switch was read by `archive`, `upload` and `server` alike and let the gateway answer `200` while discarding the uploaded body (`docs/reliability-review.md` H2). A guard that only makes sense for one command belongs on that command.
- `--delete-after-upload`: remove local file after a new upload succeeds.
- `--delete-if-exists`: remove local file on identical skip only.

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

Upload writes header then streams encrypt/copy into Put (`io.MultiReader`); at `encryption.mode=none` there is no header and the payload is stored as-is, with its digest declared in `domain.PutMeta`. Download unwraps before `DecryptAuto`. Native objects are `S3VCTR01 || S3VLT01 || chunks`. Objects without the container remain readable via the magic/type path described under [Layer ownership](#layer-ownership--every-hop-frames-its-own-layer).

### Layer ownership — every hop frames its own layer

**There is no marker of who encrypted.** `enc` answers *whether* a layer exists, never *whose*. This is the single most misunderstood part of the format, so the invariant is stated explicitly.

Each side that passes bytes on frames them in its **own** `S3VCTR01` container, and the rule for *whether* to frame is `encryption.mode` plus one exception:

| writer | frames? | why |
| --- | --- | --- |
| client, `mode=native`/`command` | yes | the container is the only carrier of `enc`, and a reader must be able to tell ciphertext from plaintext by the header alone |
| client, `mode=none` | no | there is nothing to declare: the payload is plaintext, `enc` would be the constant 0, and the only thing left in the container is the plaintext digest — which travels in `PutMeta` and in S3 user-metadata instead. The result is a bucket of ordinary files, readable by anything |
| gateway, any `mode` | yes | see below |

The gateway is a hop, not a leaf writer: it is a client of the storage in front of it, and its `mode` may be `none`. It still frames, because the container is how the next reader knows a layer was removed — and the format has no marker of whose layer that is. Without it a `mode=none` gateway would strip the client's own container as if it were its own, and the client would find nothing left. `service.Archive.WithFraming` is set only by the `server` command; it is wiring fixed by the command, not a configuration key.

| hop | code | effect |
| --- | --- | --- |
| client upload | `Archive.upload` (`internal/service/archive.go`) | client container + client payload encryption, or the bare payload at `mode=none` |
| gateway ingress (S3 facade `PutObject` **or** `CompleteMultipartUpload`) | `internal/s3api/put.go` / `multipart.go` → `UploadFile` | **frames and encrypts again**, by the gateway's own `mode` |
| gateway egress | `Fetch.Materialize` | `unwrapForDecrypt` strips the gateway container, `DecryptAuto` strips the gateway payload encryption |
| client download | `Fetch.Download` | the same two steps, on the client's `mode` |

Note that a non-s3vault S3 client (`aws s3 cp`) contributes no layer at all — it hands the gateway plaintext and the gateway's frame is the only one. **A multipart upload contributes no more than a single one either**, however many parts it arrived in: the gateway concatenates the parts *before* it frames, so `CompleteMultipartUpload` takes the same `UploadFile` path a spooled `PutObject` body does. Framing per part, or framing and then concatenating, would put one container per part into the object and leave every reader stripping the wrong one.

**The invariant:** each side strips exactly one container and at most one payload encryption. The container is stripped by magic (`container.Unwrap`, called at `internal/service/fetch.go`) **independently of `encryption.mode`**, which is why the framing rule above is load-bearing: a process must never find a layer it cannot account for. `DecryptAuto` then branches on the container's `Enc` field — the object, not the local encryptor type — and only ever sees the payload of one layer. All four server×client mode combinations are verified in `scripts/verify-layer-ownership.sh`.

Consequences, all measured (`scripts/verify-server-drift.sh`):

| writer | reader | result |
| --- | --- | --- |
| any | same `mode` | correct |
| `command` | `none` | **`rc=1`: reader refuses (`object requires encryption.mode=command`)** |
| `none` | `command` | `rc=1`: reader refuses (`object requires encryption.mode=none`); genuine legacy containerless payloads still fail inside the decrypt command |

`DecryptAuto` (`internal/adapter/encrypt/detect.go`) is handed the container's enc name (`unwrapForDecrypt` returns `container.EncName(hdr.Enc)` alongside the payload). When the container is present, the enc is authoritative: it must match the reader's `Name()`, otherwise the read fails; `enc=none` copies the payload, `enc=native`/`enc=command` invoke the matching decryptor. This closes both silent cells at once — a command ciphertext is no longer copied under `mode=none` (P1/H2), and an `enc=0` payload is no longer fed to the command decryptor (H5). Server-side `mode` drift is now refused explicitly rather than incidentally by the `x-amz-checksum-sha256` mismatch (`internal/s3api/get.go:56`) or by cryptcp failing.

An object with no `S3VCTR01` container carries no `enc`; the reader falls back to magic/type detection, and how loudly it says so depends on its own `mode` — at `mode=none` this is the shape the reader itself writes, so it logs at debug; at `native`/`command` the object was written by a process that does not match and it warns.

The residual case is a containerless object read by a `mode=none` reader, where the payload could in principle be ciphertext: there is no `enc` to compare, so detection falls back to the payload magic. Both ciphertext shapes are now checked — the native `S3VLT01` magic and OpenSSL's `Salted__` envelope — and either one makes the read **fail** rather than copy garbage out with exit code 0. The 8-byte `Salted__` prefix is not proof of ciphertext, so a plaintext file that happens to start with it is refused too, with a message naming both readings. That closes P1-legacy/H2 for the containerless shape; see `docs/decrypt-detection.md` §3.

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

Download: `unwrapForDecrypt` peeks the `S3VCTR01` container and passes its `Enc` into `DecryptAuto`, which is authoritative — `none` copies, `native`/`command` decrypt with the matching encryptor, and a mismatch with the reader's `mode` is an error. Only for objects with no container — the shape `encryption.mode=none` itself writes — does detection fall back to the payload magic and the local encryptor type, and there it refuses on either ciphertext magic rather than copying garbage. This describes one layer's payload only; which layer, and who put it there, is covered by [Layer ownership](#layer-ownership--every-hop-frames-its-own-layer).

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
- `Populate`: `singleflight` in-process + lockfile across processes; write `*.tmp` → fsync → rename. Identity change for the same id rewrites plaintext. The cross-process lock is `flock(LOCK_EX)` and is **unix-only** — `lock_other.go` compiles it to a no-op elsewhere, so two non-unix processes can populate the same entry concurrently.
- Sidecar `.meta`: unique `*.tmp` → rename (atomic); concurrent Get atime bumps must not tear JSON. Atime writes are best-effort — a read that loses the race still succeeds.
- Hard TTL (`cache.ttl`, default 168h) + max bytes LRU (`cache.max_bytes`, default **10 GiB**, `<= 0` disables; atime in meta). Get rewrites atime at most once per minute (not every hit). Expired entries are also dropped lazily on Get/Lookup.
- Soft TTL (`cache.soft_ttl`, default **20s**): within the window a Materialize hit needs **no S3** call. After soft TTL, the stale entry is served immediately and revalidation runs in the background; unchanged SHA-256/ETag only bumps `validated_at`, changed identity re-Populates. `soft_ttl: 0` forces a synchronous identity check on every request. Note that revalidation is not a bare `HEAD`: it goes through `identity.ResolveRemote`, which issues a `Head` **and** a 128-byte `GetRange`.
- Background sweeper (`cache.sweep_interval`, default **15m**, `0` = off): on `s3vault server`, periodically removes hard-TTL expired entries so unused objects do not linger until LRU pressure. First sweep runs at start.
- In-memory index (loaded at open, updated on Populate/Get/remove/Clear): O(1) `Usage`, in-memory LRU eviction, Get hits without re-reading JSON. Index miss still falls back to disk (other processes). A corrupt sidecar found by `loadIndex` at open is skipped rather than deleted; it is removed on the next `Lookup` that misses the index.
- Corrupt meta → drop entry and miss (re-Populate).
- Stampede: one download per id+identity; waiters use the same result.
- Write-through invalidation: the S3 facade drops the entry for the key it just wrote (`API.invalidateCache`, called from `handlePut` on a real write and from `handleDelete`). Without it a fresh entry inside the soft-TTL window would be served without revalidation, so a read straight after a successful `PutObject` returned the previous version. The drop is best-effort — a failing `Remove` logs a warning and leaves the entry to normal revalidation, never failing the write that already succeeded. It covers writes made **by the facade**; an `archive`/`upload` CLI run against the same backend and cache dir is only picked up by revalidation, i.e. still up to `soft_ttl` late.
- `s3vault_cache_entries` / `s3vault_cache_bytes` are only registered when the cache is enabled, so they are absent from `/metrics` under the default `cache.enabled: false`.

**Risk (when enabled):** plaintext on disk. Mitigations: loopback server bind, `0700` cache dir, short TTL, optional tmpfs, `cache clear`. Soft TTL trades up to `soft_ttl` of possible staleness for fewer backend HEADs — but not for writes made through the gateway, which invalidate the entry outright (see write-through invalidation above). Leave `cache.enabled: false` unless you need hit latency / fewer backend Gets.

## HTTP server

`s3vault server` is the **gateway** role: it owns no storage and is a client of the storage it fronts. Everything below is reasoned about the topology in [Roles and topology](#roles-and-topology), and the deployment model the read paths assume is that one:

1. All S3 clients connect **only** to the gateway's S3 facade. **Only** the gateway talks to the storage.
2. Client and gateway speak **only** the S3 protocol to each other.
3. Client encryption is the **client's own layer**; a gateway `mode` on top of it is a **second** layer.

Consequence worth stating plainly: because each side frames on its own, an object in the storage holds two nested layers whenever a gateway is on its path and the client encrypts (see [Layer ownership](#layer-ownership--every-hop-frames-its-own-layer)). Symmetric `mode` across the two sides is what makes the exchange work, and that is a configuration invariant, not something the format enforces.

### API

The gateway's plain HTTP listener carries only operational probes. Listen `127.0.0.1:8080` by default.

- `GET /health` — process alive (no backend call, no auth).
- `GET /ready` — cheap `Head(".s3vault-ready")` against the object store; `503` when unreachable.
- Metrics on a **separate** `metrics_listen` (`/metrics`).

There is no bearer token and no object route on this listener. `s3vault server` requires both `server.s3_access_key` and `server.s3_secret_key`; without them it refuses to start (`ErrS3CredsRequired` in `internal/httpserver/bind.go`), because the S3 facade is its only data frontend.

Graceful `Shutdown` on SIGTERM.

### S3 API gateway (SigV4 plaintext facade)

The gateway's only data frontend: a path-style S3 API for standard clients (`aws-cli`, SDKs). It requires `server.s3_access_key` and `server.s3_secret_key` (prefer env `S3VAULT_SERVER_S3_*`).

- **Semantics:** Put encrypts into the backend; Get/Head via `Fetch.Materialize` (disk cache + soft-TTL / SWR when `cache.enabled`, else ephemeral decrypt). Works over either backend; with `backend.type: local` and no bucket configured the facade advertises `s3vault`.
- **Auth:** AWS SigV4 via `amwolff/awsig`; credentials resolved through `port.S3Identity` (`Lookup` + `Allow`). v1 adapter is static single principal + one virtual bucket (`server.s3_bucket`, default `s3.bucket`). Optional `server.s3_bucket_as_prefix`: any client bucket is allowed and prepended to the object key under backend `s3.bucket` / `s3.prefix` (`s3://reports/a.log` → `{prefix}/reports/a.log`). Future: multi-key / bucket bindings without changing handlers.
- **Listen:** `server.s3_listen` empty → multiplex on `server.listen` (reserved first segments `health`, `ready` stay on the plain HTTP listener). Non-empty → dedicated listener (+ `/health` without auth).
- **Ops:** GetObject, PutObject, DeleteObject, ListObjectsV2, HeadObject, HeadBucket, ListBuckets, and the five multipart operations. No CreateBucket / virtual-host in v1. Listing is V2 only: a v1 request (an explicit `list-type` other than `2`, or a `marker` parameter with no `list-type`) is rejected with `501 NotImplemented` (`Code` `NotImplemented`) instead of being silently answered in V2 shape. `prefix` and `delimiter` are supported.
- **Checksum:** Get/Head/Put responses include `x-amz-checksum-sha256` (base64 of plaintext SHA-256) and `x-amz-checksum-type: FULL_OBJECT` when identity is known (identity comes from the S3VCTR01 header). Client request checksum headers are ignored in v1. The header describes **the bytes in the body**, so a ranged GET (`206`) does not carry it: S3 answers a range with the digest *of that range*, and computing one per range would mean reading it on every ranged read. Advertising the whole object's digest there instead is a false claim, and clients that verify checksums act on it — `aws s3 cp` downloads large objects in ranges and fails the whole transfer with `Expected checksum … did not match`. Pinned by `TestRangedGetOmitsWholeObjectChecksum`.
- **The client's own read-side checksum log is silenced, and that is a deliberate silence.** `manager.Uploader` asks for CRC32 *per part*, so the storage keeps a **composite** checksum — on MinIO, `x-amz-checksum-crc32: <base64>-N` with `ChecksumType: COMPOSITE` — and a checksum-of-checksums cannot be recomputed client-side. The Go SDK therefore skips validation and logs `Skipped validation of multipart checksum` at WARN, **once per GET of every object larger than the part size**. `s3store.getObject` passes `DisableLogOutputChecksumValidationSkipped` to stop it. Nothing actionable is lost: write-side integrity is the stronger guarantee and is untouched (the per-part CRC32 travels in the request and the store rejects a part that does not match), and what the warning denies is a *redundant* re-check of a value no client can reproduce — constant, not news, and the same on real S3, which is why AWS documents that clients cannot verify checksums of multipart-uploaded objects. Left on, it is one WARN per read, i.e. exactly the log an operator stops reading. It is a warning, not a failure: the read returns correct bytes either way. Pinned by the `шлюз не пишет 'Skipped validation of multipart checksum'` assertion in `phase_facade_multipart`.
- **Metrics:** existing HTTP instrumentation plus `s3vault_s3_requests_total{op,result}` (low cardinality; the multipart ops are `create_multipart`, `upload_part`, `complete_multipart`, `abort_multipart`, `list_parts`).
- Frontend S3 keys are **not** backend `s3.access_key`.

### Multipart in the facade

**The gateway implements multipart itself; the client does not know it does.** The AWS SDK uploader picks between one `PutObject` and multipart at its part size, read from the *first* chunk before `CreateMultipartUpload` is sent, and that decision belongs to the SDK, not to s3vault. A client-side fallback — probe once, spool to a temp file, retry as a single PUT — was rejected: it makes the client's behaviour depend on what the peer can do, and it cannot help past 5 GiB anyway, which is a protocol limit rather than a client one (see [docs/multipart.md](docs/multipart.md) §5).

**The part size is a writer-side choice, `s3.multipart_part_size`, default 5 MiB** (`config.DefaultMultipartPartSize`; env `S3VAULT_S3_MULTIPART_PART_SIZE`, raw bytes). It is not negotiated, not probed and not derived from what the peer accepts: the client sends that many bytes per part and any S3-compatible store — the facade included — takes whatever legal size it is handed. The bounds are S3's own and are checked twice — in `config.Normalize` and again in `s3store.New` — rather than left to the SDK, which would only object to a too-small value at the first upload, naming neither the key nor the reason. Exactly one value is exempt: **zero means "not specified"** and takes the default, the same way `archive.workers` below 1 is clamped rather than refused. That is what lets a fragment assembled by hand (`s3test.ConfigFromEnv` does exactly that for the integration suite) behave like one that came through `Load`; anything else out of range is an error naming the key (`TestMultipartPartSizeBounds`, `TestNewRejectsBadPartSize`, `TestNewDefaultsZeroPartSize`). Two consequences follow from it and both are contract, not detail:

- **The part size is the threshold above which multipart starts at all.** A body of at most one part goes out as a single `PutObject` and opens no session. The default is 5 MiB — the S3 minimum, and what the SDK used before this key existed — so 12 MiB is three parts and 4 MiB is one request. Raising the key to 25 MiB moves the threshold instead: the same 12 MiB would be a single `PutObject`, never touching multipart. Pinning both numbers is what keeps the facade's multipart path under test rather than merely reachable (`TestPutPartSizeDecidesTheSplit`, and the `дефолт:` assertions in `phase_facade_multipart`).
- **It buys throughput with memory, linearly.** The SDK keeps `Concurrency + 1` buffers of exactly `PartSize`, so the 5 MiB default costs about 30 MiB in flight at concurrency 5, and every MiB added to the key adds ~5 MiB there. The default stays at the minimum because that is both what existing deployments already do and the cheapest profile; a larger value is a per-deployment decision, not a default. `Concurrency` is deliberately left at the SDK default rather than coupled to the part size: a derived value would change upload concurrency without being a key anyone set.

The SDK also raises the part size on its own if the configured one would need more than `MaxUploadParts` parts, so a large value is not a ceiling — it is a floor on how much arrives per request.

| request | facade |
| --- | --- |
| `POST /{bucket}/{key}?uploads` | create a session, return `UploadId` |
| `PUT /{bucket}/{key}?partNumber=N&uploadId=X` | spool part N, return its `ETag` (MD5 hex, quoted) |
| `POST /{bucket}/{key}?uploadId=X` | concatenate the parts → `archive.UploadFile` → 200 with the assembled object's `ETag` |
| `DELETE /{bucket}/{key}?uploadId=X` | remove the parts and the session → 204 |
| `GET /{bucket}/{key}?uploadId=X` | `ListParts`, ascending |

Multipart is dispatched on the **query**, not on the method: every one of its operations reuses a verb that already means something else here. A `POST` with neither `uploads` nor `uploadId` is the browser form-upload shape, which is not served, and is answered `NotImplemented` rather than `MethodNotAllowed` — "recognised, deliberately unsupported", not "verb unknown". Every other unknown verb still gets `405`.

**Assembly happens before the frame, so the layer count does not change.** The assembled file goes to the storage through the ordinary `Archive.upload`, exactly like a spooled `PutObject` body: the gateway adds **one** layer of its own, on egress `Fetch.Materialize` removes that one, and the client gets its own `S3VCTR01` back. Were the parts framed and then concatenated, the object would carry one container per part and every reader would strip the wrong one. Pinned by `TestMultipartWritesOneObjectWithOneGatewayLayer`.

**Sessions.** The registry is in process memory (`internal/s3api/multipart.go`). `uploadId` is 32 bytes of `crypto/rand` in hex, because it is a bearer token for the spooled bytes: knowing it is the right to append to that upload. Every follow-up request re-checks it against both the session's `AccessKeyID` and its `backendKey`; a mismatch answers `NoSuchUpload` — not `AccessDenied` — so the id cannot be probed for existence. `s3auth.Static.Allow` authorises on the bucket alone and is deliberately left alone (`TestStaticAllowIgnoresOperation`); the binding that actually matters lives in the registry, where it keeps holding as `Allow` grows.

Parts are written to one file per part number, so concurrent `UploadPart` requests (the SDK sends five at once) never contend on the same file, and re-uploading a number replaces it as in S3. The session mutex guards the part map and the activity clock — a concurrent map write is a crash, not a race report.

**Integrity.** The part `ETag` is the MD5 of the part's bytes, by S3's definition; it is a part digest and carries no claim about the object. `CompleteMultipartUpload` checks that every listed number was uploaded (`InvalidPart`), that they ascend (`InvalidPartOrder`), that every part but the last reaches the 5 MiB minimum (`EntityTooSmall`), and that a supplied `ETag` matches — the last is best effort, since not every client echoes one back. A part that was uploaded but *not* listed is not an error: S3 assembles from the listed parts and discards the rest, and a facade that rejected this would turn away a client real S3 accepts. Assembly streams through a SHA-256, which becomes `ArchiveOptions.PlaintextSHA256` so `Archive` does not hash the file again. The object's `ETag` is `sha256(plaintext)` in quotes — the same scheme `handleGet` and `handlePut` report, deliberately **not** the S3 multipart `md5-of-md5s-N` form, because two schemes for one object would make neither usable. Parts and the session are removed **only after** a successful upload: a failure must not destroy data the client would otherwise just re-read. Write-through cache invalidation follows `handlePut` exactly.

**Disk.** The spool root is `server.multipart_dir` — its own key, **not** `cache.dir`: the cache has its own invariants (TTL, sweeper, lockfile) and is off by default, while multipart has to work in every configuration. It is `0700`, parts and the assembled copy are `0600`, and it holds client plaintext, which makes it a plaintext-on-disk surface exactly like the cache. Assembly is a sequential copy, so peak usage is roughly twice the object. `server.multipart_ttl` (24h) and `server.multipart_sweep_interval` (15m) drive `SweepExpired`, started by the `server` command; `server.multipart_max_sessions` (64) evicts the least recently touched when exceeded. Limits from the S3 specification are enforced too: 10000 parts, 5 MiB minimum, 5 GiB maximum, each message naming the actual number. **Without the sweeper an interrupted upload would keep its bytes on disk forever**, so it is part of the feature, not a nicety; the spool root is also wiped when the registry is opened, since a session never outlives its process.

**Known limits.** A session does not survive a gateway restart, and a cluster of gateways sharing one spool directory will not work — sessions are bound to a process. The final `CompleteMultipartUpload` still goes through `archive.UploadFile` → `manager.Upload`, so it is capped at 5 GiB **unless the gateway's own storage supports multipart**, in which case it flows up the stack normally. That precondition is verified against MinIO: `create-multipart-upload` against the gateway's own `s3.endpoint` returns an `UploadId`, its part `ETag` is the MD5 of the part, and its assembled object round-trips byte-identically.


### Client through a gateway

A host without CryptoPro/S3 credentials does **not** need a separate ingest protocol. It points `s3.endpoint` at the gateway's S3 facade and uses the gateway's `server.s3_access_key`/`server.s3_secret_key` as its own S3 credentials (path-style). `archive`/`upload` then apply the client's `encryption.mode` and `PutObject` the wrapped object; the gateway adds its own layer (a gateway `mode`), exactly as it would for `aws s3 cp`. Because `download` reads from the same `s3.endpoint`, the two layers are removed by two processes on the way back, and the client reads what it wrote. There is no write-only mode: writes and reads are symmetric by construction.

| gateway `mode` | client `mode` | stored object | write | read back by the client |
| --- | --- | --- | --- | --- |
| `command` | `command` | 2 layers, gateway outer / client inner | ok | ok |
| `command` | `none` | 2 layers, client inner `enc=0` | ok | ok |
| `none` | `command` | 2 layers, client inner | ok | ok |
| `none` | `none` | 2 layers, both `enc=0` | ok | ok |

The live MinIO matrix (`scripts/verify-layer-ownership.sh`) drives the s3vault client at the facade; `scripts/verify-server-drift.sh` covers a gateway losing or gaining encryption under stored objects.

Lost with the removal: the `remote.rate_limit_bps` bandwidth cap (the S3 path has no equivalent) and the `X-S3Vault-Mtime` source-mtime header (PutObject sets the container `SourceMTime` to the gateway's current time).

## Logging and metrics

`log/slog` on stderr: `time`, `level`, `msg`, `op`, path/key, size, duration, `err`. The handler is **`slog.NewTextHandler`** (`key=value`), set as the process default; the only JSON line in the binary is the secrets-in-config warning, which builds a throwaway JSON handler. Levels debug/info/warn/error, selected with `--log-level` / `log.level`. Never log credentials, PEM, or file bodies.

Prometheus (low cardinality — no full path labels) on `metrics_listen` (server) or `--metrics-listen` (one-shot CLI):

- `s3vault_files_total{op,result}` — found / uploaded / skipped / failed / downloaded
- `s3vault_bytes_total{direction}` — plaintext bytes in (`download`) and out (`upload`)
- `s3vault_upload_duration_seconds`, `s3vault_upload_size_bytes`
- `s3vault_download_duration_seconds`, `s3vault_download_size_bytes` (S3 Get+decrypt, not cache hits)
- `s3vault_cache_hits_total`, `s3vault_cache_misses_total`, `s3vault_cache_entries`, `s3vault_cache_bytes`
- `s3vault_http_request_duration_seconds`, `s3vault_http_requests_total`, `s3vault_http_requests_in_flight`, `s3vault_http_response_size_bytes` (`code`, `method` only)
- `s3vault_s3_requests_total{op,result}` — S3 API ops (`get`, `put`, `delete`, `list`, `head`, …)
- Go/process collectors on `s3vault server` only; the one-shot CLI path uses a private registry, so a single process never double-registers.

Label values are drawn entirely from a fixed constant block plus the op and HTTP status, so no key, path, or request id ever reaches a label. Note that S3 facade traffic is counted in **both** the HTTP and S3 metric families when the S3 API is multiplexed onto the main listener.

## Security constraints

- Path traversal: `filepath.IsLocal` on relative paths; HTTP must use the same mapper.
- No `bash -c`; command encrypt argv is a string slice.
- TLS verify on by default: it follows the endpoint scheme, and `https://` uses the system trust store. There is no switch to disable verification.
- Cache and dest files `0600`.
- Private keys and KEKs only from files/env, mode `0600`.

## Dependencies (why)

| Library | Why | Not chosen |
| --- | --- | --- |
| aws-sdk-go-v2 + s3 + feature/s3/manager | Retry, multipart, custom endpoint | minio-go |
| aws-sdk-go-v2/config + credentials | `LoadDefaultConfig` credential chain (env, shared config, IAM role) | hand-rolled key resolution |
| aws/smithy-go | Request signing/serialisation types used directly by the S3 client | — |
| amwolff/awsig | Server-side SigV4 for S3 API facade (UNSIGNED-PAYLOAD / streaming) | hand-roll; SeaweedFS/MinIO server packages; gofakes3 |
| cobra + viper | Subcommands + layered config | urfave/cli, koanf |
| log/slog | Stdlib structured logs | zap/zerolog |
| prometheus/client_golang | HTTP, cache, archive/upload/download metrics | — |
| golang.org/x/sync | errgroup, singleflight | hand-rolled pools |
| golang.org/x/sys | `unix.Flock` for the cross-process cache lock (`flock` is not in stdlib `os`) | `syscall.Flock` (not portable) |
| stdlib crypto | AES-GCM, RSA-OAEP | age (poor Range story) |
| testify | Tests | — |

Disk cache is custom (samber/hot is in-memory). No retry library: the AWS SDK retries S3 calls.

## Tests

Unit (`go test -race ./...`, no S3 and no `.env`): period parser, keying, identity, scanner, native/command encrypt, config (including the removed-key guard), archive skip, single-file upload, fetch download, disk cache, HTTP health/ready and S3-facade dispatch, Prometheus collectors, container, local backend (contract, keys, ranges, list, raw layout) and a CLI upload/download roundtrip over the local backend. Also present but not listed above: the S3 facade suite (`internal/s3api`, including a full multipart roundtrip through the AWS SDK uploader, the one-layer invariant, the session sweeper and the error paths), `s3auth`, `hash`, and benchmarks for the disk cache, local store, scanner and native encryptor. `internal/storetest.RunConformance` is the shared `ObjectStore` contract, exercised by both `internal/adapter/local` and the S3 integration test.

Integration (`//go:build integration`, `internal/integration`, live S3/MinIO): Put/Head/Get/skip, archive then skip, native-encrypted roundtrip, and the store conformance suite. `internal/s3test.ConfigFromEnv` walks up to 8 parent directories for a repo `.env`, lets the process env win per key, and `t.Skip`s when endpoint/bucket/access/secret are unset. Note it parses **every** `KEY=VALUE` in that file, not just `S3VAULT_*`, and injects them with `t.Setenv` (so tests using it cannot be `t.Parallel`).

End-to-end (`scripts/e2e.sh`, MinIO in compose or CI): the full server matrix, cache stampede (16 parallel GETs collapse to one entry), corrupt object (flipped AEAD tag byte must fail the download and leave no file), S3 down (`socat` proxy toggled — upload fails, `archive` exits 1, `--fail-fast` aborts early, `/ready` returns 503, recovery verified), interrupted download (128 MiB fetch appears whole or not at all, no temp left behind), graceful shutdown (SIGTERM → exit 0, port released), and a live s3vault client uploading a 12 MiB file **through the facade** — which is the multipart path, since the SDK switches at 5 MiB — with a byte-exact roundtrip and an empty spool afterwards.

Still not covered: command-mode encryption against a **real** CryptoPro provider (CI substitutes `scripts/e2e/fakecryptcp`, which is neither real cryptography nor GOST), and integration coverage of the SigV4 S3 facade itself.

CI — six workflows, all on Go 1.26, all on push/PR to `main` (plus a tag trigger for release):

| Workflow | Contents |
| --- | --- |
| `go.yml` | `go build`, `go vet`, `go test -race -shuffle=on -count=1 ./...`, a `gofmt -l` gate, a `go mod tidy` + `git diff --exit-code` job; matrix `1.26` + `stable` |
| `integration.yml` | MinIO service container, `go test -tags=integration -race ./internal/integration/` |
| `e2e.yml` | MinIO + `socat` + `awscli`, runs `./scripts/e2e.sh all`, uploads artifacts on failure |
| `lint.yml` | `golangci-lint` against `.golangci.yml` (gated on new issues only) |
| `security.yml` | `govulncheck` (gated) and `gosec` (non-blocking) |
| `release.yml` | GoReleaser on `v*` tags |

Known soft spots, both deliberate: lint runs with `only-new-issues: true`, and the `gosec` job is `continue-on-error`.

## Status

| Area | Status |
| --- | --- |
| CLI skeleton, config, slog | Done |
| Scanner, keying, archive dry-run | Done |
| S3 Head/Put/Get, identity, workers | Done |
| Native + command encryption, download | Done |
| Disk cache, HTTP health/ready, Prometheus HTTP/cache metrics | Done |
| Archive/upload/download Prometheus metrics | Done |
| `server` / `cache` commands | Done |
| `upload` command | Done |
| S3 API gateway (SigV4, Get/Put/Delete/ListV2 + Head + multipart) — sole frontend | Done |
| Local filesystem backend (`backend.type: local`, container + raw) | Done |
| MinIO integration tests (happy paths + store conformance) | Done |
| GitHub Actions (build, vet, `-race`, gofmt, tidy, lint, vulncheck, gosec, integration, e2e) | Done |
| Docker / compose, GoReleaser | Done (image never built locally — no docker daemon was available) |
| E2E phase harness (stampede, corruption, S3 down, interrupted download, shutdown) | Done |
| Real CryptoPro provider verification | Not started |
| SigV4 facade integration coverage | Not started |
| `--follow-symlinks` CLI flag (config key only today) | Not started |
