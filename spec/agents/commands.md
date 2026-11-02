# Команды

```bash
make build            # CGO_ENABLED=0 + version ldflags → ./s3vault
make test             # go test -race -count=1 ./...
go vet ./...
gofmt -l .            # `make fmt` хочет gofumpt/goimports, не установлены по умолчанию

# integration: нужен живой S3/MinIO, иначе skip
go test -tags=integration -count=1 ./internal/integration/

make e2e              # полная обвязка: MinIO из compose.e2e.yaml
make e2e-up|e2e-down  # запуск / остановка MinIO
./scripts/e2e.sh server   # одна фаза (нужен socat)

go run ./cmd/s3vault archive <dir> --older-than 7d --dry-run
```

Исследование слоёв/конвертов, нужен живой MinIO на `127.0.0.1:9000` (бакет
`s3vault`, `s3vault`/`s3vaulttest`). Все три пишут только под уникальные префиксы
и безопасны для повторного запуска:

```bash
make verify                  # все три; также шаг в .github/workflows/e2e.yml
make verify-layers           # матрица: режим server × режим client
make verify-drift            # изменение режима server под хранящимися объектами
make verify-detect           # ветки DecryptAuto, T0-T7
```

Каждая возвращает ненулевой код при нарушении контракта, поэтому работает как CI-гейт. Рабочие
директории (`/tmp/verify*`) загружаются как артефакт `verify-logs` при сбое —
тот лог содержит причину `s3 materialize` facade, которую клиенты никогда не видят
(ответ несёт голый `InternalError`).
