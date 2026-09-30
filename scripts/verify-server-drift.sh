#!/usr/bin/env bash
# Дрейф конфигурации сервера при неизменной клиентской.
# Модель: клиент ↔ фасад только по S3; сервер ↔ реальный S3.
set -uo pipefail

W=${VERIFY_WORKDIR:-/tmp/verify-drift}
MINIO=http://127.0.0.1:9000
BUCKET=s3vault
MINIO_AK=s3vault
MINIO_SK=s3vaulttest
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAKECP="$ROOT/scripts/e2e/fakecryptcp"
PREFIX="drift-$(date +%s)-$$"
FAKECK=drift-ak
FACK=drift-sk
HP=18401
SP=18651
MP=19401

rm -rf "$W"
mkdir -p "$W"
cd "$W" || exit 1

# Креды MinIO нужны с самого начала: ими заполняется окружение клиента, ими же
# проверяется живость хранилища ниже.
export AWS_ACCESS_KEY_ID="$MINIO_AK" AWS_SECRET_ACCESS_KEY="$MINIO_SK"

(cd "$ROOT" && go build -o "$W/sv" ./cmd/s3vault) || {
	echo "сборка не удалась"
	exit 1
}

# MinIO и бакет — предусловие: без них сценарии упираются в upload и дают
# ложные «отказы», которые читаются как успех.
curl -fsS --max-time 5 "$MINIO/minio/health/live" >/dev/null 2>&1 || {
	echo "MinIO не отвечает на $MINIO — стенд не запускается"
	exit 1
}
aws --endpoint-url "$MINIO" s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1 || {
	echo "бакет $BUCKET недоступен на $MINIO (создай его: aws s3api create-bucket --bucket $BUCKET)"
	exit 1
}
head -c 32 /dev/urandom >"$W/kek.bin"
printf 'facade payload\n' >"$W/f.txt"
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
export CRYPTCP="$FAKECP" E2E_FAKE_KEK="$W/kek.bin" CRYPTOPRO_PIN=1234
export AWS_ACCESS_KEY_ID="$MINIO_AK" AWS_SECRET_ACCESS_KEY="$MINIO_SK"

SRV=""
SCEN=start
stop() {
	[[ -n "$SRV" ]] || return 0
	kill -TERM "$SRV" 2>/dev/null
	wait "$SRV" 2>/dev/null
	SRV=""
}
trap stop EXIT

start_server() { # start_server <mode>
	local mode=$1
	local -a cfg=()
	[[ $mode == command ]] && cfg=(--config "$W/command.yaml")
	env S3VAULT_S3_ENDPOINT="$MINIO" S3VAULT_S3_BUCKET="$BUCKET" \
		S3VAULT_S3_ACCESS_KEY="$MINIO_AK" S3VAULT_S3_SECRET_KEY="$MINIO_SK" \
		S3VAULT_S3_PREFIX="$PREFIX" S3VAULT_ENCRYPTION_MODE="$mode" \
		S3VAULT_SERVER_S3_ACCESS_KEY="$FAKECK" \
		S3VAULT_SERVER_S3_SECRET_KEY="$FACK" S3VAULT_LOG_LEVEL=error \
		"$W/sv" server --listen "127.0.0.1:$HP" --s3-listen "127.0.0.1:$SP" \
		--metrics-listen "127.0.0.1:$MP" "${cfg[@]}" >"$W/srv-$SCEN-$mode.log" 2>&1 &
	SRV=$!
	for _ in $(seq 1 80); do
		curl -fsS --max-time 2 "http://127.0.0.1:$HP/health" >/dev/null 2>&1 && return 0
		sleep 0.25
	done
	return 1
}

client() { # client <mode> <subcmd...>
	local mode=$1
	shift
	local -a cfg=()
	[[ $mode == command ]] && cfg=(--config "$W/command.yaml")
	env S3VAULT_S3_ENDPOINT="http://127.0.0.1:$SP" S3VAULT_S3_BUCKET="$BUCKET" \
		S3VAULT_S3_ACCESS_KEY="$FAKECK" S3VAULT_S3_SECRET_KEY="$FACK" \
		S3VAULT_S3_PREFIX= S3VAULT_ENCRYPTION_MODE="$mode" \
		"$W/sv" "${cfg[@]}" "$@" >"$W/last-$SCEN.log" 2>&1
}

BUGS=0

verdict() { # verdict <подпись> <rc> <файл>
	local tag=$1 rc=$2 f=$3 sz=0
	[[ -f $f ]] && sz=$(wc -c <"$f")
	if [[ $rc -eq 0 ]] && cmp -s "$W/f.txt" "$f"; then
		printf '    %-34s плайнтекст — ВЕРНО\n' "$tag"
	elif [[ $rc -eq 0 ]]; then
		BUGS=$((BUGS + 1))
		printf '    %-34s rc=0, %s байт ≠ плайнтекст — ТИХИЙ МУСОР (ПРОВАЛ)\n' "$tag" "$sz"
	elif [[ $sz -ne 0 ]]; then
		BUGS=$((BUGS + 1))
		printf '    %-34s отказ rc=%s, но на диск ушло %s байт — НЕ ЧИСТЫЙ ОТКАЗ\n' "$tag" "$rc" "$sz"
	else
		local why
		why=$(grep -oE 'requires encryption.mode=[a-z]+|object is encrypted|corrupt header|InternalError' "$W/last-$SCEN.log" | head -1)
		printf '    %-34s отказ rc=%s, 0 байт на диске (%s)\n' "$tag" "$rc" "${why:-иное}"
	fi
}

echo "плайнтекст=$PLAIN байт; клиент ВСЕГДА mode=command"
echo "логи серверов: \$W/srv-<сценарий>-<mode>.log (причина отказа фасада пишется туда)"
echo
up() { # up <сценарий> <серверный_режим> <клиентский_режим> — записать объект
	local scen=$1 smode=$2 cmode=$3
	SCEN="$scen"
	start_server "$smode" || {
		echo "  сервер ($smode) не поднялся"
		exit 1
	}
	client "$cmode" upload "$W/f.txt" --key enc.txt >/dev/null 2>&1
	local rc=$?
	if [[ $rc -ne 0 ]]; then
		BUGS=$((BUGS + 1))
		printf '  ПРОВАЛ: запись при сервер=%s не удалась (rc=%s)\n' "$smode" "$rc"
	fi
	stop
}

echo "### A. Сервер потерял шифрование: command → none (объекты уже зашифрованы)"
up A-write command command
SCEN=A-read
start_server none || {
	echo "  сервер (none) не поднялся"
	exit 1
}
rm -f "$W/a.bin"
client command download enc.txt "$W/a.bin"
verdict "клиент читает после дрейфа" $? "$W/a.bin"
stop

echo
echo "### B. Сервер нарастил шифрование: none → command (объекты лежали открытыми)"
aws --endpoint-url "$MINIO" s3 rm "s3://$BUCKET/$PREFIX/enc.txt" >/dev/null 2>&1
up B-write none command
SCEN=B-read
start_server command || {
	echo "  сервер (command) не поднялся"
	exit 1
}
rm -f "$W/b.bin"
client command download enc.txt "$W/b.bin"
verdict "клиент читает после дрейфа" $? "$W/b.bin"
stop

echo
echo "### C. Для сравнения: клиент=none читает объект, зашифрованный сервером"
SCEN=C
start_server command || {
	echo "  сервер (command) не поднялся"
	exit 1
}
aws --endpoint-url "$MINIO" s3 rm "s3://$BUCKET/$PREFIX/enc.txt" >/dev/null 2>&1
client command upload "$W/f.txt" --key enc.txt >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
	BUGS=$((BUGS + 1))
	printf '  ПРОВАЛ: запись для сценария C не удалась\n'
fi
rm -f "$W/c.bin"
client none download enc.txt "$W/c.bin"
verdict "клиент=none, сервер=command" $? "$W/c.bin"
stop

echo
if [[ $BUGS -gt 0 ]]; then
	printf 'ИТОГ: %s провал(ов) — дрейф encryption.mode не отвергнут громко\n' "$BUGS"
	exit 1
fi
echo "ИТОГ: оба дрейфа отвергнуты, ни одного байта мусора на диске"
