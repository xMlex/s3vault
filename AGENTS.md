# AGENTS.md

Instructions for coding agents working on **s3vault**.

Before any Go coding, review, debugging, troubleshooting, or setup task, load the `samber/cc-skills-golang@golang-how-to` skill first — it routes to whichever other Go skills the task needs.

Read [architecture.md](architecture.md) before changing pipelines, encryption, S3 identity, cache, or HTTP. Do not invent a second identity scheme or a second ciphertext format.

## What this repo is

Go CLI (`github.com/xMlex/s3vault`) that archives files older than a period to S3-compatible storage, optionally encrypts client-side, downloads/decrypts, and can serve plaintext over HTTP (optional persistent disk cache, off by default).

Operator docs (build, deploy, encryption modes): [README.md](README.md).

Entry: `cmd/s3vault`. Logic: `internal/`. No public `pkg/`.

## Skills to load by task

`golang-how-to` first, then:

| Work | Also load |
| --- | --- |
| CLI / flags / exit codes | `golang-cli`, `golang-spf13-cobra`, `golang-spf13-viper` |
| New packages, layout | `golang-project-layout`, `golang-design-patterns`, `golang-structs-interfaces`, `golang-naming` |
| S3, crypto, paths, commands | `golang-security`, `golang-safety` |
| Workers, singleflight, shutdown | `golang-concurrency`, `golang-context` |
| slog / Prometheus | `golang-observability` |
| Tests | `golang-testing`, `golang-stretchr-testify` |
| go.mod / new libraries | `golang-popular-libraries`, `golang-dependency-management` |
| CI / goreleaser | `golang-continuous-integration`, `golang-lint` |
| Errors / wrapping | `golang-error-handling` |

Do not add a DI container. Manual constructors only.

Fix typos as soon as they show up (code, comments, docs, `.env` keys). Do not keep compatibility aliases for misspellings.

## Hard rules

- Interfaces: small, in `internal/port` or at the consumer. Return structs from adapters. `var _ port.X = (*T)(nil)`.
- Stream I/O. No `ReadAll` of user files or S3 bodies.
- Object identity: S3VCTR01 Range header (plaintext SHA-256 in body), or Head fields from legacy S3 user-metadata. Never treat ETag as content hash. `layout=raw` stores plaintext only (no content-hash skip).
- RSA must not encrypt payloads; envelope AES-256-GCM only (`S3VLT01`). Magic bytes, not extensions.
- External encrypt/decrypt: `exec.CommandContext` with argv slices, never a shell. No secrets in argv.
- Logs: `log/slog` JSON to stderr. Output/summaries to stdout. Redact keys, PEM, tokens, file contents.
- Config: flags > `S3VAULT_*` > file > defaults. Config file optional.
- After successful archive, keep local files unless `--delete-after-upload`. On identical skip, keep unless `--delete-if-exists`.
- Symlinks: skip by default; follow only inside the scan root.
- Cache: `cache.enabled` (default false). When on, stores plaintext (`0600`/`0700`, hex paths, atomic rename, `singleflight` + lockfile); soft TTL (`cache.soft_ttl`, default 20s) then SWR; sweeper (`cache.sweep_interval`, default 15m). When off, HTTP/S3 Materialize uses an ephemeral temp per request.
- HTTP: default bind `127.0.0.1`; Range via `http.ServeContent` on Materialize plaintext. `PUT /files/{path...}` ingest for remote archive clients (`remote.url` + `S3VAULT_SERVER_TOKEN`). Optional S3 SigV4 facade (`S3VAULT_SERVER_S3_*`, multiplex or `s3_listen`) shares Fetch/Archive with `/files`.
- Cobra: `RunE`, `SilenceUsage`/`SilenceErrors`, `cmd.OutOrStdout()`, no `os.Exit` inside commands.
- Tests: table-driven, `t.Parallel` where safe, integration behind `//go:build integration`. `go test -race`.
- New dependencies: only if stdlib is insufficient; justify in architecture.md.

## Commands

```bash
go test ./...
go test -race ./...
go run ./cmd/s3vault archive <dir> --older-than 7d --dry-run
golangci-lint run ./...
```

Example config: `s3vault.example.yaml`.

## Not done yet (do not pretend they exist)

- Docker / MinIO integration tests / GitHub Actions

Implement those against architecture.md, not a new design, unless the user explicitly revises the architecture document.
