# AGENTS.md

Instructions for coding agents working on **s3vault**.

## Before you start

1. Load the `samber/cc-skills-golang@golang-how-to` skill before any Go coding, review, debugging, troubleshooting, or setup task — it routes to whichever other Go skills the task needs.
2. Read [architecture.md](architecture.md) before touching pipelines, encryption, S3 identity, cache, or HTTP. It is the source of truth for component boundaries and formats — implement against it, not a new design, unless the user explicitly revises it. Do not invent a second identity scheme or a second ciphertext format.

## What this repo is

Go CLI (`github.com/xMlex/s3vault`, `go 1.26`) that archives files older than a period to S3-compatible storage or a local directory, optionally encrypts client-side, downloads/decrypts, and can serve plaintext over an S3 API facade (SigV4; persistent disk cache optional, off by default).

| | |
| --- | --- |
| Entry | `cmd/s3vault` (`main`: signals, exit codes, version ldflags) |
| Logic | `internal/` only; no public `pkg/` |
| Operator docs | [README.md](README.md) — build, deploy, encryption modes |
| Config examples | `s3vault.example.yaml`, `.env.example` |
| Tooling | `Makefile` (`make build`, `make test`, `make lint`, `make fmt`) |

## Hard rules

**Interfaces and I/O**

- Interfaces: small, in `internal/port` or at the consumer. Adapters return concrete structs, not interfaces. Compile-time check: `var _ port.X = (*T)(nil)`.
- No DI container. Manual constructors only.
- Stream I/O. No `ReadAll` of user files or S3 bodies.

**Identity and crypto**

- Object identity: `S3VCTR01` Range header (plaintext SHA-256 in body), or Head fields from legacy S3 user-metadata. Never treat ETag as a content hash.
- Default object layout is the `S3VCTR01` container, so `backend.type: local` stores the same bytes as S3. `backend.local.layout=raw` is the exception: it stores the bare plaintext payload (no container), which drops the `enc` marker, so it is only valid with `encryption.mode=none` (config rejects `raw` + `native`/`command` at startup). There is no stored content hash and archive never content-skips. An incoming container is stripped whatever its `enc`. Mechanism: [architecture.md](architecture.md#local-filesystem-backend).
- RSA must not encrypt payloads; envelope AES-256-GCM only (`S3VLT01`). Detect by magic bytes, never by extension.
- External encrypt/decrypt: `exec.CommandContext` with argv slices, never a shell. No secrets in argv (env only).
- **Every hop wraps its own layer; there is no "whose layer" marker in the format.** Each s3vault process puts its own `S3VCTR01` on the bytes it passes, so a stored object holds as many layers as there are s3vault processes on the `origin → storage` path — two when a gateway is on it, one when it is not. `container.Unwrap` strips the container by magic regardless of `mode`; `DecryptAuto` then branches on the container's `Enc` and refuses a reader whose `encryption.mode` does not match (objects without a container fall back to legacy magic/type detection with a warning; a `layout=raw` store logs that at debug, since containerless is its normal shape). A read strips exactly **one** layer, so a gateway on the write path must also be on the read path. Full mechanism and measured failure table: [architecture.md](architecture.md#layer-ownership--every-hop-wraps-its-own-layer), reproduced by `make verify-layers`.
- A host without CryptoPro/S3 points `s3.endpoint` at the gateway's **S3 facade** and uses `server.s3_access_key`/`server.s3_secret_key` as S3 credentials (path-style). Every object then holds two nested layers (gateway outer, client inner) and the client reads back through the same gateway, so writes and reads are symmetric. The `remote.url` HTTP ingest address, the bearer `HTTP /files` frontend, and `server.token` are removed; their config keys are rejected at startup (`config.CheckRemovedKeys`).

**Roles** — the vocabulary is fixed; do not introduce a synonym

Three nouns cover the whole system, and `architecture.md` §[Roles and topology](architecture.md#roles-and-topology) is the source of truth. Write docs and comments in these terms.

- **Storage** — where objects live: `backend.type: s3` (AWS, MinIO, any S3-compatible API) or `local` (a directory). The only place bytes are persisted.
- **Client** — an s3vault process that reads from or writes to the storage: `archive`, `upload`, `download`. It has no storage of its own.
- **Gateway** — `s3vault server`. No storage of its own either: it fronts the storage, serves plaintext, and is at the same time a client of that storage (one `newObjectStore` `ObjectStore` serves its reads and the S3 facade's Put/List/Delete). Its **only** data frontend is the **S3 facade** (SigV4); the HTTP listener carries just `/health` and `/ready`.

Two rules follow, and both are load-bearing:

- **"server" in the command name means gateway, not storage.** Never use it to mean a third-party S3 server — that is *storage*. Do not add a `role:` / `mode:` config key: the role is fixed by the command, and a second source of truth can only contradict the first, exactly like the forbidden `s3.tls`. A role is never called a "mode"; `mode` is reserved for `encryption.mode`.
- **Layer count = number of s3vault processes that wrapped the bytes**, and a read strips exactly one. Hence "two nested layers" in any doc means "a gateway is on this path" — say that instead. A non-s3vault S3 client (`aws s3 cp`) is transparent and contributes no layer.

**Runtime behavior**

- Logs: `log/slog` JSON to stderr. Output/summaries to stdout. Redact keys, PEM, tokens, and file contents.
- Config precedence: flags > `S3VAULT_*` env > file > defaults. Config file is optional.
- After a successful archive, keep local files unless `--delete-after-upload`. On identical skip, keep them unless `--delete-if-exists`.
- Symlinks: skip by default; follow only inside the scan root.
- Cache: `cache.enabled` default **false**; when on, plaintext lands on disk, so the file modes, hex paths, atomic rename, `singleflight`+lockfile, soft TTL then SWR, and the sweeper are all load-bearing — see [architecture.md](architecture.md#cache) before touching them. Never let cached entries cross an `encryption.mode` boundary; the cache id already mixes in the encryptor fingerprint.
- HTTP: default bind `127.0.0.1`; the plain HTTP listener serves only `/health` and `/ready`. Object data is served **only** by the SigV4 S3 facade (`S3VAULT_SERVER_S3_*`, required; multiplex or `s3_listen`). `server.token`, the bearer `HTTP /files` frontend, and `remote.url` are removed; the removed keys are rejected at startup.
- Cobra: `RunE`, `SilenceUsage`/`SilenceErrors`, `cmd.OutOrStdout()`, no `os.Exit` inside commands.
- S3 endpoint scheme is the only TLS switch: `https://` verifies the certificate against the system store, `http://` disables TLS. Do not add a `s3.tls` boolean — it can only contradict the URL while looking like it works. `TestEnvKeysMatchConfigFields` guards the general rule that every config field is bound and every bound key has a field.

**Repo hygiene**

- Fix typos as soon as they show up (code, comments, docs, `.env` keys). Do not keep compatibility aliases for misspellings.
- Never commit secrets or key material. `.env`, `.env.*.local`, `kek.bin`, and `*.pem` stay out of git.
- New dependencies: only if stdlib is insufficient; justify in `architecture.md`.

## Tests

- Table-driven, `t.Parallel` where safe, `go test -race`. Integration tests build behind `//go:build integration`.
- Integration tests live in `internal/integration` and need a live S3/MinIO. `internal/s3test.ConfigFromEnv` reads the repo `.env` (process env wins) and `t.Skip`s unless `S3VAULT_S3_ENDPOINT`, `S3VAULT_S3_BUCKET`, `S3VAULT_S3_ACCESS_KEY`, and `S3VAULT_S3_SECRET_KEY` are set.
- Unit tests must stay runnable without any S3 and without `.env`.

## Lint

The tree is **not** lint-clean: hundreds of pre-existing `wsl_v5`-style findings predate current work. Do not mass-fix them. Check only your own delta:

```bash
golangci-lint run --new-from-rev=HEAD ./...
```

## Commands

```bash
make build            # CGO_ENABLED=0 + version ldflags → ./s3vault
make test             # go test -race -count=1 ./...
go vet ./...
gofmt -l .            # `make fmt` wants gofumpt/goimports, not installed by default

# integration: needs a live S3/MinIO, otherwise skips
go test -tags=integration -count=1 ./internal/integration/

make e2e              # full harness: MinIO from compose.e2e.yaml
make e2e-up|e2e-down  # start / stop MinIO
./scripts/e2e.sh server   # one phase (needs socat)

go run ./cmd/s3vault archive <dir> --older-than 7d --dry-run
```

Layer/envelope investigation, needs a live MinIO on `127.0.0.1:9000` (bucket
`s3vault`, `s3vault`/`s3vaulttest`). All three write only under unique prefixes
and are safe to re-run:

```bash
make verify                  # all three; also a step in .github/workflows/e2e.yml
make verify-layers           # matrix: server mode × client mode
make verify-drift            # server mode changes under stored objects
make verify-detect           # DecryptAuto branches, T0-T7
```

Each returns non-zero on a contract violation, so they work as CI gates. Working
dirs (`/tmp/verify*`) are uploaded as the `verify-logs` artifact on failure —
that log holds the facade's `s3 materialize` reason, which clients never see
(the response carries a bare `InternalError`).

## E2E harness

`compose.e2e.yaml` + `scripts/e2e.sh`. Mechanics are commented in the script; these are the traps:

- `encryption.mode=command` is exercised by substituting `cryptcp` with `scripts/e2e/fakecryptcp`, which mirrors the real contract (argv, `CRYPTOPRO_THUMBPRINT` from env, key from the SHA-1 thumbprint) but is **not cryptography and not GOST**. It tests the pipeline, not CryptoPro.
- The `go` phase runs unit tests with **no `S3VAULT_*` in the environment** — only the binary and `-tags=integration` get it (the `S3_ENV` array). `S3VAULT_S3_PREFIX` would clobber the local-backend prefix tests.
- The prefix is unique per run (`S3VAULT_E2E_RUN_ID`), or a re-run sees the previous objects and gets skip instead of upload.
- S3 failure is faked with a `socat` proxy rather than `docker compose stop`, so the phase needs no Docker rights.
- Contracts the harness pins rather than repairs: object key relative to the scan root; `S3VLT01` at offset 128 inside `S3VCTR01`; identity from the CRC header, with no body read on `Head` (so a corrupt AEAD tag is only caught by `download`); a remote client's `s3.prefix` becoming part of the key and stacking with the server's.

## CI

`.github/workflows/`, on push/PR to `main`: `go.yml` (build, vet, `go test -race -shuffle=on -count=1`, gofmt, tidy-check; matrix `1.26` + `stable`), `lint.yml` (golangci-lint), `security.yml` (govulncheck — gate; gosec — `continue-on-error`), `integration.yml` and `e2e.yml` (MinIO service container), `release.yml` + `.goreleaser.yml` (tags `v*`).

Two escape hatches are calibration, not oversight — both drop out when the debt is paid:

- `lint.yml` uses `only-new-issues: true`. The tree carries hundreds of pre-existing findings (the bulk are `wsl_v5`) and AGENTS.md forbids mass-fixing them; new violations still fail the build. Re-measure with `golangci-lint run ./...` rather than trusting any count recorded here.
- The `gosec` job is `continue-on-error` for the same reason (mostly G304 "file inclusion via variable" — which is this CLI's actual job). Suppressing them silently would blind the gate to genuine future findings.

Version pinning is per job, not global: `tidy` must run on `1.26` or `stable` rewrites `go.mod`. MinIO is pinned to a release tag, never `:latest`, so red/green does not depend on the registry. CI brings its own MinIO service container and creates the bucket with awscli — the code never calls `CreateBucket` (compare `minio-init` in `compose.e2e.yaml`).

## Not done yet (do not pretend they exist)

- `Dockerfile` is written but has **never been built**: the agent has no access
  to the docker daemon (`/var/run/docker.sock`). Only what is checkable without a
  daemon was verified — the `go build` line yields a static binary with a correct
  version, `goreleaser check`/`goreleaser build` are green. Run the first
  `docker build` yourself.

- **Reader mode is validated against the object header.** `DecryptAuto`
  (`internal/adapter/encrypt/detect.go`) branches on the `S3VCTR01` `Enc` field
  returned by `unwrapForDecrypt`, not on the local encryptor type. With a
  container present, a reader whose `encryption.mode` differs from `enc` fails
  loudly (`object requires encryption.mode=…`) instead of writing ciphertext —
  this covers both the `command → none` silent corruption (P1/H2 in
  problems.md) and the mirror `enc=0` case (H5). Objects with no container
  (legacy) log a warning and fall back to magic/type detection. Mechanism and
  history: `docs/decrypt-detection.md`, reproduced by the `scripts/verify-*.sh`
  trio.

