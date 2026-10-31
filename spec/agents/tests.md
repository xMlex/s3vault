# Тесты

- Table-driven, `t.Parallel` где безопасно, `go test -race`. Integration-тесты собираются под `//go:build integration`.
- Integration-тесты лежат в `internal/integration` и требуют живой S3/MinIO. `internal/s3test.ConfigFromEnv` читает `.env` репозитория (process env имеет приоритет) и делает `t.Skip`, если не заданы `S3VAULT_S3_ENDPOINT`, `S3VAULT_S3_BUCKET`, `S3VAULT_S3_ACCESS_KEY` и `S3VAULT_S3_SECRET_KEY`.
- Unit-тесты должны запускаться без S3 и без `.env`.
