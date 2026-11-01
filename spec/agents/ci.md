# CI

`.github/workflows/`, при push/PR в `main`: `go.yml` (build, vet, `go test -race -shuffle=on -count=1`, gofmt, tidy-check; матрица `1.26` + `stable`), `lint.yml` (golangci-lint, версия закреплена), `security.yml` (govulncheck — гейт; gosec — информационный полный прогон), `integration.yml` и `e2e.yml` (MinIO шагом + PostgreSQL service container), `release.yml` + `.goreleaser.yml` (теги `v*`). `go.yml` и `e2e.yml` умеют запускаться вручную (`workflow_dispatch`); `e2e.yml` гоняет `scripts/e2e.sh all`, включая фазу `index` (локальный индекс дайджестов и ETag без MinIO).

MinIO не запускается как service container: GitHub не даёт передать ему command, а образу нужен `server /data`. Кроме того, MinIO убрал образы с Docker Hub, поэтому оба workflow делают `docker run` шагом из `cgr.dev/chainguard/minio`, закреплённого по digest, и ждут `/minio/health/ready`.

Два escape hatch — калибровка, а не упущение:

- `lint.yml` использует `only-new-issues: true`. Дерево несёт сотни предсуществующих находок (основная масса — `wsl_v5`), и AGENTS.md запрещает массово их исправлять; новые нарушения всё равно валят сборку. Перемеряйте через `golangci-lint run ./...`, а не доверяйте любому числу, записанному здесь.
- `gosec` в `security.yml` — информационный: полный прогон печатает warning и не валит workflow. Standalone gosec не понимает `//nolint:gosec` и на осознанных G115/G302/G501 всегда красный; новые находки гейтит `lint.yml`, где gosec включён в `.golangci.yml`.

Закрепление версий — по задачам, а не глобальное: `tidy` должен работать на `1.26`, иначе `stable` перепишет `go.mod`. MinIO закреплён на release-теге, никогда не `:latest`, чтобы красное/зелёное не зависело от реестра. CI поднимает собственный MinIO service container и создаёт бакет через awscli — код никогда не вызывает `CreateBucket` (сравните `minio-init` в `compose.e2e.yaml`).
