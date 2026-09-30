#!/bin/sh
# Пример архивирования каталога через шлюз: example/command/gateway.sh.
#
# usage: ./example/command/archive.sh <dir> <older-than> [prefix]
#   <dir>        каталог-источник (сканируется рекурсивно)
#   <older-than> период для --older-than: 7d, 24h, 1w, 30d, 90m
#   [prefix]     префикс ключей в бакете (по умолчанию — без префикса)
#
# У клиента ключей шифрования нет (encryption.mode=none): объект шифрует шлюз.
# Читается тем же путём — `s3vault download <key> <file>` с этим окружением.
set -eu

dir="${1:?usage: archive.sh <dir> <older-than> [prefix]}"
older="${2:?usage: archive.sh <dir> <older-than> [prefix]}"
prefix="${3:-}"
args_add="${4:-}"

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
S3VAULT_BIN="${S3VAULT_BIN:-$root/s3vault}"

# s3.* смотрит на S3-фасад шлюза, а не в хранилище.
export S3VAULT_S3_ENDPOINT="${S3VAULT_S3_ENDPOINT:-http://127.0.0.1:8333}"
export S3VAULT_S3_BUCKET="${S3VAULT_S3_BUCKET:-my-bucket}" # = виртуальный бакет фасада
export S3VAULT_S3_ACCESS_KEY="${S3VAULT_S3_ACCESS_KEY:-vaultak}"
export S3VAULT_S3_SECRET_KEY="${S3VAULT_S3_SECRET_KEY:-vaultsk}"
export S3VAULT_S3_PATH_STYLE=true
export S3VAULT_ENCRYPTION_MODE=none # у клиента нет ключей; шифрует шлюз

set -- archive "$dir" --older-than "$older" $args_add

if [ -n "$prefix" ]; then
	set -- "$@" --prefix "$prefix"
fi

exec "$S3VAULT_BIN" "$@"
