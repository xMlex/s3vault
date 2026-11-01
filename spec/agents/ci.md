# CI

`.github/workflows/`, при push/PR в `main`: `go.yml` (build, vet, `go test -race -shuffle=on -count=1`, gofmt, tidy-check; матрица `1.26` + `stable`), `lint.yml` (golangci-lint), `security.yml` (govulncheck — гейт; gosec — `continue-on-error`), `integration.yml` и `e2e.yml` (MinIO service container), `release.yml` + `.goreleaser.yml` (теги `v*`). `go.yml` и `e2e.yml` умеют запускаться вручную (`workflow_dispatch`); `e2e.yml` гоняет `scripts/e2e.sh all`, включая фазу `index` (локальный индекс дайджестов и ETag без MinIO).

Два escape hatch — калибровка, а не упущение — оба отпадут, когда долг выплачен:

- `lint.yml` использует `only-new-issues: true`. Дерево несёт сотни предсуществующих находок (основная масса — `wsl_v5`), и AGENTS.md запрещает массово их исправлять; новые нарушения всё равно валят сборку. Перемеряйте через `golangci-lint run ./...`, а не доверяйте любому числу, записанному здесь.
- Задача `gosec` — `continue-on-error` по той же причине (в основном G304 «включение файла через переменную» — это и есть реальная работа этого CLI). Тихое подавление ослепило бы гейт к подлинным будущим находкам.

Закрепление версий — по задачам, а не глобальное: `tidy` должен работать на `1.26`, иначе `stable` перепишет `go.mod`. MinIO закреплён на release-теге, никогда не `:latest`, чтобы красное/зелёное не зависело от реестра. CI поднимает собственный MinIO service container и создаёт бакет через awscli — код никогда не вызывает `CreateBucket` (сравните `minio-init` в `compose.e2e.yaml`).
