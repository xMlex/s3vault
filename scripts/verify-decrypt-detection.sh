#!/usr/bin/env bash
# Верификация гипотез по маршрутам чтения. Go-код не меняется: только бинарь и S3.
set -uo pipefail

W=${VERIFY_WORKDIR:-/tmp/verify}
MINIO=http://127.0.0.1:9000
BUCKET=s3vault
AK=s3vault
SK=s3vaulttest
PREFIX="verify-$(date +%s)-$$"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAKECP="$ROOT/scripts/e2e/fakecryptcp"

rm -rf "$W"
mkdir -p "$W"
cd "$W" || exit 1

# Креды MinIO нужны с самого начала: ими заполняется окружение клиента, ими же
# проверяется живость хранилища ниже.
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK"

(cd "$ROOT" && go build -o "$W/sv" ./cmd/s3vault) || {
	echo "сборка не удалась"
	exit 1
}

# MinIO и бакет — предусловие. Без этой проверки стенд молча «проходит» на
# пустом хранилище: все T-сценарии упираются в upload и дают ложные вердикты.
curl -fsS --max-time 5 "$MINIO/minio/health/live" >/dev/null 2>&1 || {
	echo "MinIO не отвечает на $MINIO — стенд не запускается"
	exit 1
}
aws --endpoint-url "$MINIO" s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1 || {
	echo "бакет $BUCKET недоступен на $MINIO (создай его: aws s3api create-bucket --bucket $BUCKET)"
	exit 1
}

head -c 32 /dev/urandom >"$W/kek.bin"
printf 'verify payload\n' >"$W/f.txt"
printf 'plaintext obj\n' >"$W/plain.txt"
PLAIN=$(wc -c <"$W/f.txt")

cat >"$W/command.yaml" <<YAML
encryption:
  mode: command
  command:
    provider: cryptopro
    thumbprint: afa43c43975fbfc700f051fd62016e1571e7e025
    encrypt: ["$ROOT/scripts/cryptcp-encrypt"]
    decrypt: ["$ROOT/scripts/cryptcp-decrypt"]
    timeout: 5m
YAML

cat >"$W/cache.yaml" <<YAML
cache:
  enabled: true
  dir: "$W/cache"
  ttl: 1h
YAML

export S3VAULT_S3_ENDPOINT="$MINIO" S3VAULT_S3_BUCKET="$BUCKET"
export S3VAULT_S3_ACCESS_KEY="$AK" S3VAULT_S3_SECRET_KEY="$SK"
export S3VAULT_S3_PREFIX="$PREFIX"
export CRYPTCP="$FAKECP" E2E_FAKE_KEK="$W/kek.bin" CRYPTOPRO_PIN=1234
# aws тоже ходит в MinIO напрямую — нужны его собственные креды.
export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK"

BUGS=0
verdict() { printf '  %-4s %s\n' "$1" "$2"; }
ok() { verdict "OK" "$1"; }
# bad — реальный провал инварианта. Считается, чтобы скрипт возвращал ненулевой
# код: без счётчика стенд в CI печатал бы BUG и выходил с 0.
bad() {
	BUGS=$((BUGS + 1))
	verdict "BUG" "$1"
}
note() { verdict "INFO" "$1"; }

# Любой непредвиденный сбой (MinIO не отвечает, бинарь не собрался, сервер не
# поднялся) — тоже провал, иначе стенд молча «проходит» на пустом стенде.
fail_env() {
	BUGS=$((BUGS + 1))
	printf '  %-4s %s\n' "BUG" "$1"
	exit 1
}

PIDS=()
stop_all() {
	for p in "${PIDS[@]:-}"; do
		[[ -n "$p" ]] || continue
		kill -TERM "$p" 2>/dev/null
		wait "$p" 2>/dev/null
	done
	PIDS=()
}
trap stop_all EXIT

start() { # start <port> <s3port> <metricsport> [config] [VAR=VAL ...]
	local port=$1 s3port=$2 mport=$3 cfg=${4:-}
	shift 3
	[[ -n "$cfg" && "$cfg" == -* ]] && cfg=""
	local -a envs=()
	while [[ $# -gt 0 && "$1" == *=* && "$1" != -* ]]; do envs+=("$1"); shift; done
	local -a args=(--listen "127.0.0.1:$port" --metrics-listen "127.0.0.1:$mport")
	[[ -n "$s3port" ]] && args+=(--s3-listen "127.0.0.1:$s3port")
	[[ -n "$cfg" ]] && args+=(--config "$cfg")
	env "${envs[@]:+${envs[@]}}" \
		S3VAULT_SERVER_S3_ACCESS_KEY=facade-ak S3VAULT_SERVER_S3_SECRET_KEY=facade-sk \
		S3VAULT_LOG_LEVEL=error "$W/sv" server "${args[@]}" \
		>/dev/null 2>&1 &
	PIDS+=($!)
	for _ in $(seq 1 60); do
		curl -fsS --max-time 2 "http://127.0.0.1:$port/health" >/dev/null 2>&1 && return 0
		sleep 0.25
	done
	return 1
}

echo "### T0 базовый объект: что шифрует сервер"
"$W/sv" --config "$W/command.yaml" upload "$W/f.txt" --key enc.txt >/dev/null 2>&1
aws --endpoint-url "$MINIO" s3api get-object --bucket "$BUCKET" \
	--key "$PREFIX/enc.txt" "$W/enc.raw" >/dev/null 2>&1
SZ=$(wc -c <"$W/enc.raw")
CT=$((SZ - 128))
ENC=$(od -An -tu1 -j52 -N1 "$W/enc.raw" | tr -d ' ')
note "plaintext=$PLAIN байт, объект=$SZ, шифротекст=$CT, enc=$ENC"
[[ "$ENC" == "2" ]] && ok "объект помечен command (enc=2)" || bad "enc=$ENC, ожидался 2"

echo
echo "### T1 remote.url удалён: ключи S3VAULT_REMOTE_URL/S3VAULT_SERVER_TOKEN отвергаются"
S3VAULT_REMOTE_URL="http://127.0.0.1:1" S3VAULT_ENCRYPTION_MODE=none \
	"$W/sv" download "$PREFIX/enc.txt" "$W/t1.out" >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
	ok "S3VAULT_REMOTE_URL отвергнут (rc=$rc) — remote-режим удалён"
else
	bad "S3VAULT_REMOTE_URL всё ещё принимается"
fi

echo
echo "### T2 mode=none читает command-объект (CLI download)"
rm -f "$W/t2.out"
S3VAULT_ENCRYPTION_MODE=none "$W/sv" download "$PREFIX/enc.txt" "$W/t2.out" >/dev/null 2>&1
rc=$?
SZ2=0
[[ -f "$W/t2.out" ]] && SZ2=$(wc -c <"$W/t2.out")
if [[ $rc -eq 0 && $SZ2 -eq $CT ]]; then
	bad "rc=0 и $SZ2 байт шифротекста в файле — отказа не было"
	note "пользователь получил мусор с кодом успеха"
else
	ok "отказ (rc=$rc, $SZ2 байт)"
fi

echo
echo "### T3 mode=command читает тот же объект (эталон)"
rm -f "$W/t3.out"
"$W/sv" --config "$W/command.yaml" download "$PREFIX/enc.txt" "$W/t3.out" >/dev/null 2>&1
rc=$?
if [[ $rc -eq 0 ]] && cmp -s "$W/f.txt" "$W/t3.out"; then
	ok "mode=command даёт плайнтекст (rc=0, байты совпали)"
else
	bad "mode=command не дал плайнтекст (rc=$rc)"
fi

echo
echo "### T4 S3-фасад GetObject, сервер в mode=none против command-объекта"
start 18091 18341 19091 || fail_env "сервер не поднялся на 18091/18341/19091"
# Ключ фасада — относительно его префикса (как facade/aws.txt в стенде).
# Ожидается отказ САМОГО ДЕТЕКТОРА: hdr.Enc=command против читателя mode=none,
# поэтому DecryptAuto возвращает ошибку, тело не пишется вовсе, и наружу уходит
# 500 с пустым InternalError. Отвергнут ли ответ по checksum — уже не важно:
# шифротекста в теле нет и криптопроцесс не запускается.
rm -f "$W/t5.out"
env AWS_ACCESS_KEY_ID=facade-ak AWS_SECRET_ACCESS_KEY=facade-sk \
	AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true \
	aws --endpoint-url "http://127.0.0.1:18341" s3api get-object \
	--bucket "$BUCKET" --key "enc.txt" "$W/t5.out" >"$W/t5.err" 2>&1
rc=$?
SZ5=0
[[ -f "$W/t5.out" ]] && SZ5=$(wc -c <"$W/t5.out")
if [[ $rc -ne 0 && $SZ5 -eq 0 ]]; then
	ok "отказ rc=$rc, тело пустое — детектор не отдал шифротекст"
	sed -n '1,2p' "$W/t5.err"
elif [[ $rc -ne 0 ]] && grep -q "checksum" "$W/t5.err" && [[ $SZ5 -eq $CT ]]; then
	bad "при этом переданное тело — $SZ5 байт, побайтово это шифротекст"
	note "клиент поймал по checksum, но тело всё равно утекло в файл"
else
	bad "фасад вернул $SZ5 байт (или отдал тело при отказе), rc=$rc"
	sed -n '1,2p' "$W/t5.err"
fi
stop_all

echo
echo "### T5 что кэш сохраняет в mode=none"
start 18092 "" 19092 "$W/cache.yaml" || fail_env "сервер с кэшем не поднялся на 18092/19092"
env AWS_ACCESS_KEY_ID=facade-ak AWS_SECRET_ACCESS_KEY=facade-sk \
	AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true \
	aws --endpoint-url "http://127.0.0.1:18092" s3api get-object \
	--bucket "$BUCKET" --key "enc.txt" "$W/t6.out" >/dev/null 2>&1 || true
note "файлы кэша: $(find "$W/cache" -type f -printf '%f=%s ' 2>/dev/null)"
CACHED=$(find "$W/cache" -type f -printf '%s\n' 2>/dev/null | sort -n | head -1)
if [[ -n "${CACHED:-}" && "$CACHED" -eq $CT ]]; then
	bad "в кэш ушли $CACHED байт шифротекста — кэш кэширует баг"
	note "в пределах одного mode кэш стабильно отдаёт мусор"
elif [[ -n "${CACHED:-}" ]]; then
	ok "в кэше $CACHED байт"
else
	ok "кэш пуст: отказ детектора происходит до записи хоть одного байта"
fi
stop_all

echo
echo "### T6 симметричный случай: enc=0 читаем в mode=command"
S3VAULT_ENCRYPTION_MODE=none "$W/sv" upload "$W/plain.txt" --key plain.txt >/dev/null 2>&1
rm -f "$W/t7.out"
"$W/sv" --config "$W/command.yaml" download "$PREFIX/plain.txt" "$W/t7.out" >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
	ok "отказ rc=$rc — читатель command не трогает объект с enc=0"
else
	bad "rc=0 — объект с enc=0 всё ещё ушёл в расшифровщик"
fi

echo
echo "### T7 покрытие detect.go"
(cd "$ROOT" && go test -coverprofile="$W/cov.out" ./internal/adapter/encrypt/ >/dev/null 2>&1)
note "$(cd "$ROOT" && go tool cover -func="$W/cov.out" 2>/dev/null | rg 'detect.go' || echo 'нет данных')"

echo
if [[ $BUGS -gt 0 ]]; then
	printf 'ИТОГ: %s провал(ов) — детектор шифрования нарушает контракт\n' "$BUGS"
	exit 1
fi
echo "ИТОГ: все проверки пройдены"
