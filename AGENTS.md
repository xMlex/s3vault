# AGENTS.md

Instructions for coding agents working on **s3vault**.

## Before you start

1. Load the `samber/cc-skills-golang@golang-how-to` skill before any Go coding, review, debugging, troubleshooting, or setup task — it routes to whichever other Go skills the task needs.
2. Read [architecture.md](architecture.md) before touching pipelines, encryption, S3 identity, cache, or HTTP. It is the source of truth for component boundaries and formats. Do not invent a second identity scheme or a second ciphertext format.

## What this repo is

Go CLI (`github.com/xMlex/s3vault`, `go 1.26`) that archives files older than a period to S3-compatible storage or a local directory, optionally encrypts client-side, downloads/decrypts, and can serve plaintext over HTTP (persistent disk cache optional, off by default).

| | |
| --- | --- |
| Entry | `cmd/s3vault` (`main`: signals, exit codes, version ldflags) |
| Logic | `internal/` only; no public `pkg/` |
| Operator docs | [README.md](README.md) — build, deploy, encryption modes |
| Config examples | `s3vault.example.yaml`, `.env.example` |
| Tooling | `Makefile` (`make build`, `make test`, `make lint`, `make fmt`) |

## Skills by task

`golang-how-to` first, then:

| Work | Also load |
| --- | --- |
| CLI / flags / exit codes | `golang-cli`, `golang-spf13-cobra`, `golang-spf13-viper` |
| New packages / layout | `golang-project-layout`, `golang-design-patterns`, `golang-structs-interfaces`, `golang-naming` |
| S3, crypto, paths, external commands | `golang-security`, `golang-safety` |
| Workers, singleflight, shutdown | `golang-concurrency`, `golang-context` |
| slog / Prometheus | `golang-observability` |
| Tests | `golang-testing`, `golang-stretchr-testify` |
| Benchmarks / hot paths | `golang-benchmark`, `golang-performance` |
| Refactor, rename, move code | `golang-refactoring`, `golang-gopls`, `golang-modernize` |
| go.mod / new libraries | `golang-popular-libraries`, `golang-dependency-management` |
| CI / lint | `golang-continuous-integration`, `golang-lint` |
| Errors / wrapping | `golang-error-handling` |

Do not add a DI container. Manual constructors only.

## Hard rules

**Interfaces and I/O**

- Interfaces: small, in `internal/port` or at the consumer. Adapters return concrete structs, not interfaces. Compile-time check: `var _ port.X = (*T)(nil)`.
- Stream I/O. No `ReadAll` of user files or S3 bodies.

**Identity and crypto**

- Object identity: `S3VCTR01` Range header (plaintext SHA-256 in body), or Head fields from legacy S3 user-metadata. Never treat ETag as a content hash.
- `layout=raw` stores plaintext only (no container header) and requires `encryption.mode=none`. The local store derives plaintext SHA-256 from the file (in-memory memo keyed by size+mtime) so GET/HEAD expose `ETag`/`x-amz-checksum-sha256`; `Store.StoresPlaintext()` keeps `archive` from hashing local files, so raw never content-skips.
- RSA must not encrypt payloads; envelope AES-256-GCM only (`S3VLT01`). Detect by magic bytes, never by extension.
- External encrypt/decrypt: `exec.CommandContext` with argv slices, never a shell. No secrets in argv (env only).

**Runtime behavior**

- Logs: `log/slog` JSON to stderr. Output/summaries to stdout. Redact keys, PEM, tokens, and file contents.
- Config precedence: flags > `S3VAULT_*` env > file > defaults. Config file is optional.
- After a successful archive, keep local files unless `--delete-after-upload`. On identical skip, keep them unless `--delete-if-exists`.
- Symlinks: skip by default; follow only inside the scan root.
- Cache: `cache.enabled` default **false**. When on: plaintext on disk (`0600`/`0700`, hex paths, atomic rename, `singleflight` + lockfile), soft TTL (`cache.soft_ttl`, default 20s) then SWR, sweeper (`cache.sweep_interval`, default 15m). When off, HTTP/S3 materialize uses an ephemeral temp per request.
- HTTP: default bind `127.0.0.1`; Range via `http.ServeContent` on materialized plaintext. `PUT /files/{path...}` ingest for remote archive clients (`remote.url` + `S3VAULT_SERVER_TOKEN`). Optional SigV4 S3 facade (`S3VAULT_SERVER_S3_*`, multiplex or `s3_listen`) shares Fetch/Archive with `/files`.
- Cobra: `RunE`, `SilenceUsage`/`SilenceErrors`, `cmd.OutOrStdout()`, no `os.Exit` inside commands.

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
golangci-lint run --new-from-rev=HEAD ./...

# integration: needs a live S3/MinIO, otherwise skips
go test -tags=integration -count=1 ./internal/integration/

go run ./cmd/s3vault archive <dir> --older-than 7d --dry-run
```

## CI

`.github/workflows/go.yml` runs on push/PR to `main`: `go build -v ./...` and `go test -v ./...` (Go 1.26). It has **no** `-race`, lint, gosec/govulncheck, or integration job — run those locally before release.

## Not done yet (do not pretend they exist)

- Dockerfile / compose, and a MinIO service for CI.
- CI hardening: `-race`, golangci-lint, gosec, govulncheck, integration job, GoReleaser.
- Integration coverage is partial: MinIO happy paths are covered (Put/Head/Get/skip, encrypted roundtrip, store conformance); cache stampede, corrupt object, S3 down, interrupted download, and graceful shutdown are not.

Implement these against `architecture.md`, not a new design, unless the user explicitly revises the architecture document.
