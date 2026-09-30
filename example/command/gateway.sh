#!/bin/sh
# Пример шлюза s3vault: backend S3 + encryption.mode=command, где внешняя
# команда — openssl, а ключ выводится из thumbprint получателя.
#
# Это демонстрация конвейера, НЕ криптография и НЕ ГОСТ: симметричный AES на
# значении thumbprint, без сертификатов и без CryptoPro. s3vault передаёт
# thumbprint внешней команде в переменной CRYPTOPRO_THUMBPRINT, поэтому openssl
# читает его через -pass env:CRYPTOPRO_THUMBPRINT; один и тот же ключ на
# encrypt и decrypt даёт roundtrip.
#
# Запуск:  ./example/command/gateway.sh [listen]
# Стенд по умолчанию — MinIO из compose.e2e.yaml:  make e2e-up
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
S3VAULT_BIN="${S3VAULT_BIN:-$root/s3vault}"

listen="${1:-127.0.0.1:8333}"

# ── Хранилище: доступ шлюза к S3 (backend.type=s3 по умолчанию) ──
export S3VAULT_S3_ENDPOINT="${S3VAULT_S3_ENDPOINT:-http://127.0.0.1:9000}"
export S3VAULT_S3_REGION="${S3VAULT_S3_REGION:-us-east-1}"
export S3VAULT_S3_BUCKET="${S3VAULT_S3_BUCKET:-s3vault}" # реальный бакет в хранилище
export S3VAULT_S3_ACCESS_KEY="${S3VAULT_S3_ACCESS_KEY:-s3vault}"
export S3VAULT_S3_SECRET_KEY="${S3VAULT_S3_SECRET_KEY:-s3vaulttest}"
export S3VAULT_S3_PATH_STYLE="${S3VAULT_S3_PATH_STYLE:-true}"

# ── СКЗИ: command = openssl, ключ из thumbprint ──
export S3VAULT_ENCRYPTION_MODE=command
export S3VAULT_ENCRYPTION_COMMAND_PROVIDER="${S3VAULT_ENCRYPTION_COMMAND_PROVIDER:-openssl}"
# Демо-значение: это не отпечаток сертификата, а общий секрет примера.
export S3VAULT_ENCRYPTION_COMMAND_THUMBPRINT="${S3VAULT_ENCRYPTION_COMMAND_THUMBPRINT:-0123456789abcdef0123456789abcdef01234567}"
# argv-списки в env — через запятую (в YAML нагляднее). s3vault добавит
# CRYPTOPRO_THUMBPRINT к окружению команды, openssl прочитает его через -pass.
export S3VAULT_ENCRYPTION_COMMAND_ENCRYPT="openssl,enc,-aes-256-ctr,-salt,-pbkdf2,-iter,100000,-md,sha256,-pass,env:CRYPTOPRO_THUMBPRINT"
export S3VAULT_ENCRYPTION_COMMAND_DECRYPT="openssl,enc,-d,-aes-256-ctr,-salt,-pbkdf2,-iter,100000,-md,sha256,-pass,env:CRYPTOPRO_THUMBPRINT"
export S3VAULT_ENCRYPTION_COMMAND_TIMEOUT="${S3VAULT_ENCRYPTION_COMMAND_TIMEOUT:-30m}"

# ── S3-фасад: ключи, по которым в шлюз ходят клиенты ──
export S3VAULT_SERVER_S3_ACCESS_KEY="${S3VAULT_SERVER_S3_ACCESS_KEY:-vaultak}"
export S3VAULT_SERVER_S3_SECRET_KEY="${S3VAULT_SERVER_S3_SECRET_KEY:-vaultsk}"
export S3VAULT_SERVER_S3_BUCKET="${S3VAULT_SERVER_S3_BUCKET:-my-bucket}" # виртуальный бакет

exec "$S3VAULT_BIN" server --s3-listen "$listen"
