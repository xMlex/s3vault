#!/usr/bin/env bash
# Модель развёртывания: клиент ↔ s3vault server ТОЛЬКО по S3 (фасад),
# сервер ↔ реальный S3. Шифрование клиента — его слой, сервера — свой.
# Матрица строится честно: объект каждый раз создаёт клиент СВОЕГО режима
# ЧЕРЕЗ фасад, затем тот же клиент читает его через фасад.
set -uo pipefail

W=${VERIFY_WORKDIR:-/tmp/verify-layers}
MINIO=http://127.0.0.1:9000
BUCKET=s3vault
MINIO_AK=s3vault
MINIO_SK=s3vaulttest
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAKECP="$ROOT/scripts/e2e/fakecryptcp"
PREFIX="lay-$(date +%s)-$$"
FAKECK=lay-ak
FACK=lay-sk
HP=18301
SP=18551
MP=19301

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

# MinIO и бакет — предусловие: без них матрица молча разъезжается на пустых
# ключах и «проходит», не проверив ни одной клетки.
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

# Прямой доступ в реальный S3 — только чтобы посчитать слои.
s3raw() {
	aws --endpoint-url "$MINIO" s3api get-object --bucket "$BUCKET" \
		--key "$PREFIX/enc.txt" "$1" >/dev/null 2>&1
}

# Клиент ходит ТОЛЬКО в фасад.
facade() {
	local mode=$1
	shift
	env S3VAULT_S3_ENDPOINT="http://127.0.0.1:$SP" S3VAULT_S3_BUCKET="$BUCKET" \
		S3VAULT_S3_ACCESS_KEY="$FAKECK" S3VAULT_S3_SECRET_KEY="$FACK" \
		S3VAULT_S3_PREFIX= S3VAULT_ENCRYPTION_MODE="$mode" "$@"
}

PIDS=()
stop() {
	for p in "${PIDS[@]:-}"; do
		[[ -n "$p" ]] || continue
		kill -TERM "$p" 2>/dev/null
		wait "$p" 2>/dev/null
	done
	PIDS=()
}
trap stop EXIT

start_server() {
	local mode=$1
	local -a cfg=()
	[[ $mode == command ]] && cfg=(--config "$W/command.yaml")
	env S3VAULT_S3_ENDPOINT="$MINIO" S3VAULT_S3_BUCKET="$BUCKET" \
		S3VAULT_S3_ACCESS_KEY="$MINIO_AK" S3VAULT_S3_SECRET_KEY="$MINIO_SK" \
		S3VAULT_S3_PREFIX="$PREFIX" S3VAULT_ENCRYPTION_MODE="$mode" \
		S3VAULT_SERVER_S3_ACCESS_KEY="$FAKECK" S3VAULT_SERVER_S3_SECRET_KEY="$FACK" \
		S3VAULT_LOG_LEVEL=error \
		"$W/sv" server --listen "127.0.0.1:$HP" --s3-listen "127.0.0.1:$SP" \
		--metrics-listen "127.0.0.1:$MP" "${cfg[@]}" >"$W/srv-$mode.log" 2>&1 &
	PIDS+=($!)
	for _ in $(seq 1 80); do
		curl -fsS --max-time 2 "http://127.0.0.1:$HP/health" >/dev/null 2>&1 && return 0
		sleep 0.25
	done
	return 1
}

# Сколько слоёв в объекте: 1 слой = 128 + 39 = 167, 2 слоя = 128+128+39 = 295.
layers() {
	s3raw "$W/o.bin" || {
		echo "нет объекта"
		return
	}
	local sz
	sz=$(wc -c <"$W/o.bin")
	local n
	n=$((sz / 128))
	printf '%s байт, %s слой(ёв)' "$sz" "$((sz > 200 ? 2 : 1))"
	printf ', внешний=%s' "$(dd if="$W/o.bin" bs=1 skip=128 count=8 status=none 2>/dev/null |
		xxd -p | tr -d '\n' | cut -c1-16)"
}

BUGS=0

check() { # check <клиентский_режим> <файл> <rc>
	local mode=$1 f=$2 rc=$3 sz=0
	[[ -f $f ]] && sz=$(wc -c <"$f")
	if [[ $rc -eq 0 ]] && cmp -s "$W/f.txt" "$f"; then
		printf '    чтение: плайнтекст %s байт — ВЕРНО\n' "$sz"
	elif [[ $rc -eq 0 ]]; then
		# rc=0 с неверными байтами — единственный недопустимый исход: тихий
		# мусор на диске. Это провал, а не «просто отказ».
		BUGS=$((BUGS + 1))
		printf '    чтение: rc=0, %s байт ≠ плайнтекст — ТИХИЙ МУСОР (ПРОВАЛ)\n' "$sz"
	elif [[ $sz -ne 0 ]]; then
		BUGS=$((BUGS + 1))
		printf '    чтение: отказ rc=%s, но на диск ушло %s байт — ПРОВАЛ\n' "$rc" "$sz"
	else
		printf '    чтение: отказ rc=%s, 0 байт — громко\n' "$rc"
	fi
}

echo "плайнтекст = $PLAIN байт; 1 слой = 167 байт; 2 слоя = 295 байт"
echo
for smode in command none; do
	echo "### сервер=$smode"
	start_server "$smode" || {
		echo "  сервер не поднялся"
		exit 1
	}
	for cmode in command none; do
		aws --endpoint-url "$MINIO" s3 rm "s3://$BUCKET/$PREFIX/enc.txt" >/dev/null 2>&1
		cfg=()
		[[ $cmode == command ]] && cfg=(--config "$W/command.yaml")
		facade "$cmode" "$W/sv" "${cfg[@]}" upload "$W/f.txt" --key enc.txt >/dev/null 2>&1
		printf '  клиент=%-7s запись через фасад: %s\n' "$cmode" "$(layers)"
		rm -f "$W/out.bin"
		facade "$cmode" "$W/sv" "${cfg[@]}" download enc.txt "$W/out.bin" \
			>"$W/out.log" 2>&1
		check "$cmode" "$W/out.bin" $?
		sed 's/^/      /' "$W/out.log" | rg -v "object store ready" | head -1
	done
	stop
	echo
done

if [[ $BUGS -gt 0 ]]; then
	printf 'ИТОГ: %s провал(ов) — владение слоями нарушено\n' "$BUGS"
	exit 1
fi
echo "ИТОГ: все 4 клетки матрицы дают плайнтекст"
