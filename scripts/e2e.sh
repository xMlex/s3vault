#!/usr/bin/env bash
# E2E-стенд s3vault: поднимает MinIO, гоняет CLI / HTTP-сервер / S3-фасад /
# HTTP-сервер (health/ready) и S3-фасад / локальный бэкенд против живого хранилища.
#
#   scripts/e2e.sh            # всё (MinIO поднимается сам)
#   scripts/e2e.sh up         # только MinIO
#   scripts/e2e.sh down       # снести стенд вместе с данными
#   scripts/e2e.sh clean      # снести стенд и удалить рабочий каталог
#   scripts/e2e.sh local      # локальный бэкенд, MinIO не нужен
#   scripts/e2e.sh go|cli|encrypt|server|facade|local|resilience
#
# Переопределяется через окружение:
#   S3VAULT_E2E_MINIO_API=9000 S3VAULT_E2E_HTTP_PORT=18080 \
#   S3VAULT_E2E_S3_PORT=18333 S3VAULT_E2E_METRICS_PORT=19090 \
#   S3VAULT_E2E_WORK=/tmp/s3vault-e2e
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT/compose.e2e.yaml"
COMPOSE=(docker compose -f "$COMPOSE_FILE")

# Workdir по умолчанию — per-uid: иначе два пользователя, гоняющие стенд на одной
# машине, делят каталог и ломают друг другу сборку бинаря и кэш.
WORK="${S3VAULT_E2E_WORK:-${TMPDIR:-/tmp}/s3vault-e2e-$(id -u)}"
VAULT_BIN="$WORK/s3vault"
VAULT_LOG="$WORK/vault.log"
FAKE_CRYPTCP="$ROOT/scripts/e2e/fakecryptcp"

MINIO_API_PORT="${S3VAULT_E2E_MINIO_API:-9000}"
S3_ACCESS="${S3VAULT_E2E_S3_ACCESS_KEY:-s3vault}"
S3_SECRET="${S3VAULT_E2E_S3_SECRET_KEY:-s3vaulttest}"
S3_BUCKET="${S3VAULT_E2E_S3_BUCKET:-s3vault}"

HTTP_PORT="${S3VAULT_E2E_HTTP_PORT:-18080}"
S3_PORT="${S3VAULT_E2E_S3_PORT:-18333}"
METRICS_PORT="${S3VAULT_E2E_METRICS_PORT:-19090}"

MINIO_URL="http://127.0.0.1:${MINIO_API_PORT}"
HTTP_URL="http://127.0.0.1:${HTTP_PORT}"
S3API_URL="http://127.0.0.1:${S3_PORT}"
METRICS_URL="http://127.0.0.1:${METRICS_PORT}"

FACADE_AK="e2eaccess"
FACADE_SK="e2esecretkey0123456789abcdef"
# Префикс уникален на прогон: иначе повторный запуск видит объекты прошлого и
# получает skip вместо upload, ломая счётчики и окно для --metrics-listen.
RUN_ID="${S3VAULT_E2E_RUN_ID:-$$-$(date +%s)}"
PREFIX="e2e-$RUN_ID"
REGION="us-east-1"

PASSED=0
FAILED=0
declare -a FAILURES=()
CURRENT_PHASE=""
VAULT_PID=""

if [[ -t 1 ]]; then
	C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'
else
	C_RED=""; C_GREEN=""; C_BOLD=""; C_OFF=""
fi

# ---------------------------------------------------------------- helpers ---

log() { printf '%s==>%s %s\n' "$C_BOLD" "$C_OFF" "$*"; }
pass() { PASSED=$((PASSED + 1)); printf '  %sok%s    %s\n' "$C_GREEN" "$C_OFF" "$1"; }

fail() {
	FAILED=$((FAILED + 1))
	FAILURES+=("${CURRENT_PHASE}: $1")
	printf '  %sFAIL%s  %s\n' "$C_RED" "$C_OFF" "$1"
	[[ -n "${2:-}" ]] && printf '        %s\n' "$2"
	return 0
}

assert_eq() {
	local desc=$1 got=$2 want=$3
	if [[ "$got" == "$want" ]]; then pass "$desc"; else fail "$desc" "want='$want' got='$got'"; fi
}

assert_ne() {
	local desc=$1 got=$2 unwanted=$3
	if [[ "$got" != "$unwanted" ]]; then pass "$desc"; else fail "$desc" "must not be '$unwanted'"; fi
}

assert_lt() {
	local desc=$1 got=$2 limit=$3
	if [[ "$got" =~ ^[0-9]+$ ]] && ((got < limit)); then
		pass "$desc"
	else
		fail "$desc" "want < $limit, got '$got'"
	fi
}

assert_contains() {
	local desc=$1 haystack=$2 needle=$3
	if [[ "$haystack" == *"$needle"* ]]; then
		pass "$desc"
	else
		fail "$desc" "missing '$needle' in: $(printf '%s' "$haystack" | head -c 400)"
	fi
}

assert_not_contains() {
	local desc=$1 haystack=$2 needle=$3
	if [[ "$haystack" != *"$needle"* ]]; then
		pass "$desc"
	else
		fail "$desc" "unexpected '$needle' in: $(printf '%s' "$haystack" | head -c 400)"
	fi
}

assert_ok() {
	local desc=$1
	shift
	if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc" "command failed: $*"; fi
}

assert_fails() {
	local desc=$1
	shift
	if "$@" >/dev/null 2>&1; then
		fail "$desc" "command unexpectedly succeeded: $*"
	else
		pass "$desc"
	fi
}

assert_same_bytes() {
	local desc=$1 want=$2 got=$3
	if cmp -s "$want" "$got"; then
		pass "$desc"
	else
		fail "$desc" "cmp $(wc -c <"$want" 2>/dev/null || echo '?') vs $(wc -c <"$got" 2>/dev/null || echo '?'): $want != $got"
	fi
}

assert_status() {
	local desc=$1 want=$2 got=$3
	if [[ "$got" == "$want" ]]; then pass "$desc"; else fail "$desc" "want HTTP $want, got $got"; fi
}

# ArchiveStats — единственный источник stdout для archive/upload (--output json).
stat_field() { printf '%s' "$1" | jq -r ".$2 // \"missing\""; }

wait_for() {
	local desc=$1
	shift
	local i
	for i in $(seq 1 150); do
		"$@" >/dev/null 2>&1 && return 0
		sleep 0.2
	done
	fail "timeout: $desc"
	return 1
}

# Тестовая сборка не нуждается в VCS-стампинге, а репозиторий может быть
# недоступен git из-под пользователя запуска (detached volume, dubious ownership).
# Поэтому гасим его для всех go-вызовов скрипта.
export GOFLAGS="${GOFLAGS:-} -buildvcs=false"

# Окружение видят и бинарь s3vault, и go test -tags=integration
# (internal/s3test берёт процессное окружение с приоритетом над .env).
#
# ВАЖНО: это массив, а не экспорт. Любой S3VAULT_* в окружении процесса ломает
# юнит-тесты (S3VAULT_S3_PREFIX подменяет префикс в тестах локального бэкенда,
# S3VAULT_LOG_LEVEL глушит info-логи), а AGENTS.md требует, чтобы unit-тесты
# проходили без S3 и без .env. Поэтому окружение получают только те процессы,
# которым оно нужно: бинарь s3vault и integration-тесты.
S3_ENV=(
	"S3VAULT_S3_ENDPOINT=$MINIO_URL"
	"S3VAULT_S3_BUCKET=$S3_BUCKET"
	"S3VAULT_S3_REGION=$REGION"
	"S3VAULT_S3_PATH_STYLE=true"
	"S3VAULT_S3_ACCESS_KEY=$S3_ACCESS"
	"S3VAULT_S3_SECRET_KEY=$S3_SECRET"
	"S3VAULT_S3_PREFIX=$PREFIX"
)
# Переменные для AWS CLI / MinIO, которым S3VAULT_* не мешает.
export AWS_ACCESS_KEY_ID="$S3_ACCESS"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET"
export AWS_DEFAULT_REGION="$REGION"

# vault [VAR=VAL ...] <args...>
# Ведущие присваивания уходят в окружение процесса, остальное — аргументы CLI.
# Переданные вызывающим VAR=VAL идут после S3_ENV и потому перекрывают его.
# stderr не трогаем: вызывающий сам решает, писать его в отчёт или в лог.
vault() {
	local envs=()
	while [[ $# -gt 0 && "$1" == *=* && "$1" != -* ]]; do envs+=("$1"); shift; done
	env "${S3_ENV[@]}" ${envs[@]+"${envs[@]}"} "$VAULT_BIN" "$@"
}

# Прямой доступ к бэкенду мимо s3vault — «а что реально лежит в S3».
s3_get_raw() { aws --endpoint-url "$MINIO_URL" s3api get-object --bucket "$S3_BUCKET" --key "$1" "$2" >/dev/null; }

s3_put_raw() { aws --endpoint-url "$MINIO_URL" s3api put-object --bucket "$S3_BUCKET" --key "$1" --body "$2" >/dev/null; }

s3_head_raw() { aws --endpoint-url "$MINIO_URL" s3api head-object --bucket "$S3_BUCKET" --key "$1" >/dev/null 2>&1; }

sha256_hex() { sha256sum "$1" | cut -d' ' -f1; }

# --- управляемый TCP-прокси до MinIO: им имитируем отказ S3 ---
# Прячем stdout в /dev/null, иначе wait в фазе поймает фоновые job-ы прокси.
PROXY_PID=""
proxy_up() {
	local port=$1
	command -v socat >/dev/null || {
		fail "socat не найден — без него нечем имитировать отказ S3"
		return 1
	}
	socat -T 5 "TCP-LISTEN:$port,bind=127.0.0.1,reuseaddr,fork" \
		"TCP:127.0.0.1:${MINIO_API_PORT}" >/dev/null 2>&1 &
	PROXY_PID=$!
	wait_for "socat-прокси на $port" bash -c "curl -fsS --max-time 2 http://127.0.0.1:$port/minio/health/ready"
}

proxy_down() {
	[[ -n "$PROXY_PID" ]] || return 0
	kill "$PROXY_PID" 2>/dev/null || true
	wait "$PROXY_PID" 2>/dev/null || true
	PROXY_PID=""
}

# ----------------------------------------------------------------- server ---

# start_vault [nowait] [VAR=VAL ...] [args...]
start_vault() {
	local wait_health=1
	if [[ "${1:-}" == "nowait" ]]; then wait_health=0; shift; fi
	local envs=()
	while [[ $# -gt 0 && "$1" == *=* && "$1" != -* ]]; do envs+=("$1"); shift; done

	: >"$VAULT_LOG"
	env "${S3_ENV[@]}" ${envs[@]+"${envs[@]}"} \
		S3VAULT_SERVER_S3_ACCESS_KEY="$FACADE_AK" \
		S3VAULT_SERVER_S3_SECRET_KEY="$FACADE_SK" \
		S3VAULT_LOG_LEVEL="${S3VAULT_LOG_LEVEL:-info}" \
		"$VAULT_BIN" server \
		--listen "127.0.0.1:${HTTP_PORT}" \
		--s3-listen "127.0.0.1:${S3_PORT}" \
		--metrics-listen "127.0.0.1:${METRICS_PORT}" \
		"$@" >>"$VAULT_LOG" 2>&1 &
	VAULT_PID=$!
	if [[ $wait_health -eq 1 ]]; then
		wait_for "s3vault server /health" curl -fsS "$HTTP_URL/health" || return 1
	fi
	# nowait обязан вернуть 0: иначе `start_vault nowait || return` в фазе
	# отказа уронит фазу на ложном «провале».
	return 0
}

# Останавливает сервер и возвращает код его выхода (0 = graceful shutdown).
stop_vault() {
	[[ -n "$VAULT_PID" ]] || return 0
	local rc=0
	kill -TERM "$VAULT_PID" 2>/dev/null || true
	wait "$VAULT_PID" || rc=$?
	VAULT_PID=""
	return $rc
}

cleanup() {
	local rc=$?
	stop_vault >/dev/null 2>&1 || true
	proxy_down >/dev/null 2>&1 || true
	if [[ $rc -ne 0 && -s "$VAULT_LOG" ]]; then
		printf '\n%s--- s3vault server log (tail) ---%s\n' "$C_BOLD" "$C_OFF"
		sed 's/^/        | /' "$VAULT_LOG" | tail -25
	fi
	return $rc
}
trap cleanup EXIT

# -------------------------------------------------------------------- up ---

# Падаем до сборки с внятным текстом, а не с "permission denied" от go build.
preflight_work() {
	mkdir -p "$WORK" 2>/dev/null || true
	if [[ ! -d "$WORK" || ! -w "$WORK" ]]; then
		printf 'рабочий каталог %s недоступен на запись (uid=%s)\n' "$WORK" "$(id -u)" >&2
		printf 'укажи свой: S3VAULT_E2E_WORK=... %s\n' "${0##*/}" >&2
		return 1
	fi
	# Остатки от другого пользователя: бинарь перезаписывать нельзя.
	for stale in "$VAULT_BIN" "$VAULT_LOG"; do
		[[ -e "$stale" && ! -w "$stale" ]] && rm -f "$stale" 2>/dev/null || true
	done
}

build_vault() {
	preflight_work
	(cd "$ROOT" && CGO_ENABLED=0 go build -o "$VAULT_BIN" ./cmd/s3vault)
}

wait_minio() { wait_for "minio $MINIO_URL" curl -fsS "$MINIO_URL/minio/health/ready"; }

export S3VAULT_E2E_S3_ACCESS_KEY="$S3_ACCESS" S3VAULT_E2E_S3_SECRET_KEY="$S3_SECRET"
export S3VAULT_E2E_S3_BUCKET="$S3_BUCKET" S3VAULT_E2E_MINIO_API="$MINIO_API_PORT"
export S3VAULT_E2E_MINIO_CONSOLE="${S3VAULT_E2E_MINIO_CONSOLE:-9001}"

start_minio() {
	# MinIO может быть поднят заранее (CI-сервис, чужой стенд) — тогда compose
	# не трогаем, а просто ждём готовности эндпоинта.
	if [[ "${S3VAULT_E2E_NO_COMPOSE:-0}" == "1" ]]; then
		wait_minio
		return $?
	fi
	"${COMPOSE[@]}" up -d minio
	wait_minio
	"${COMPOSE[@]}" run --rm minio-init
}

phase_up() {
	build_vault
	start_minio
}

phase_down() { "${COMPOSE[@]}" down -v --remove-orphans; }

# -------------------------------------------------------------------- go ---

phase_go() {
	log "unit + integration тесты против живого MinIO"
	wait_minio
	# unit-тесты — без S3-переменных, иначе они видят чужой prefix и log level.
	if (cd "$ROOT" && go test -race -count=1 ./...) >"$WORK/go-unit.log" 2>&1; then
		pass "go test -race ./... (юнит, без S3 и без .env)"
	else
		fail "go test -race ./..." "$(tail -20 "$WORK/go-unit.log")"
	fi
	if (cd "$ROOT" && env "${S3_ENV[@]}" go test -tags=integration -count=1 ./internal/integration/) \
		>"$WORK/go-int.log" 2>&1; then
		pass "go test -tags=integration ./internal/integration/ (живой MinIO)"
	else
		fail "integration" "$(tail -20 "$WORK/go-int.log")"
	fi
}

# ------------------------------------------------------------------- cli ---

phase_cli() {
	log "CLI: archive / upload / download, политики, симлинки, multipart, метрики"
	wait_minio
	local src="$WORK/src"
	rm -rf "$src"
	mkdir -p "$src/arch" "$src/pol" "$src/link" "$src/multipart"

	# Ключ объекта = s3.prefix + путь ОТНОСИТЕЛЬНО сканируемого корня, поэтому
	# archive $src/arch над единственным hello.txt кладёт объект в $PREFIX/hello.txt.
	# Каталоги разведены, чтобы счётчики found/skipped не зависели друг от друга.
	printf 's3vault e2e payload\n' >"$src/arch/hello.txt"
	touch -d '2020-01-01T00:00:00Z' "$src/arch/hello.txt"

	local out
	# dry-run не обращается к хранилищу.
	out=$(vault archive "$src/arch" --older-than 1d --dry-run --output json 2>/dev/null)
	assert_eq "dry-run: found=1, uploaded=0" \
		"$(stat_field "$out" found)/$(stat_field "$out" uploaded)" "1/0"

	# Первый прогон — upload, второй — skip по идентичности из S3VCTR01.
	out=$(vault archive "$src/arch" --older-than 1d --output json 2>/dev/null)
	assert_eq "archive #1: uploaded=1 skipped=0" \
		"$(stat_field "$out" uploaded)/$(stat_field "$out" skipped)" "1/0"
	out=$(vault archive "$src/arch" --older-than 1d --output json 2>/dev/null)
	assert_eq "archive #2: skip по идентичности контейнера" \
		"$(stat_field "$out" uploaded)/$(stat_field "$out" skipped)" "0/1"

	assert_ok "объект archive лежит в $PREFIX/hello.txt" s3_head_raw "$PREFIX/hello.txt"

	# --- фильтр по возрасту: до сих пор каждый файл в стенде отдалён в 2020,
	# поэтому --older-than проверял только прокидывание флага, но никогда не
	# отсекал. Здесь обе ветки: «слишком свежий -> не найден» и дефолт 7d.
	mkdir -p "$src/fresh" "$src/recent" "$src/ancient"
	printf 'fresh file\n' >"$src/fresh/now.txt"
	printf 'two days old\n' >"$src/recent/two_days.txt"
	printf 'ancient\n' >"$src/ancient/old.txt"
	touch -d '2 days ago' "$src/recent/two_days.txt"
	touch -d '2020-01-01T00:00:00Z' "$src/ancient/old.txt"

	out=$(vault archive "$src/fresh" --older-than 1d --dry-run --output json 2>/dev/null)
	assert_eq "свежий файл отсекается --older-than 1d (found=0)" "$(stat_field "$out" found)" "0"

	# Без флага работает дефолт archive.older_than=7d: два дня < 7 дней.
	out=$(vault archive "$src/recent" --dry-run --output json 2>/dev/null)
	assert_eq "дефолт 7d отсекает файл двухдневной давности" "$(stat_field "$out" found)" "0"
	out=$(vault archive "$src/ancient" --dry-run --output json 2>/dev/null)
	assert_eq "дефолт 7d берёт файл 2020 года (found=1)" "$(stat_field "$out" found)" "1"

	# Мусорный период — внятная ошибка и ненулевой код, а не падение с трассировкой.
	local rc=0 verr
	verr=$(vault archive "$src/ancient" --older-than bogus --dry-run 2>&1 >/dev/null) || rc=$?
	assert_eq "мусорный --older-than -> exit 1" "$rc" "1"
	assert_contains "мусорный --older-than объясняет проблему" "$verr" 'invalid duration "bogus"'

	# --- приоритет флагов над окружением: --prefix обязан подменить
	# S3VAULT_S3_PREFIX=$PREFIX. Если подмена сломается, объект уедет в
	# "$PREFIX/flagprefix/..." вместо "flagprefix/..." — и это поймается.
	local flagprefix="flagprefix-$RUN_ID"
	out=$(vault archive "$src/arch" --older-than 1d --prefix "$flagprefix" --output json 2>/dev/null)
	assert_eq "--prefix: uploaded=1" "$(stat_field "$out" uploaded)" "1"
	assert_ok "--prefix подменил env-префикс" s3_head_raw "$flagprefix/hello.txt"
	assert_fails "--prefix не сложился с env-префиксом" s3_head_raw "$PREFIX/$flagprefix/hello.txt"

	# --bucket обязан дойти до хранилища: несуществующий бакет даёт failed>0.
	# Если бы флаг игнорировался, прогон по существующему бакету прошёл бы успешно.
	out=$(vault archive "$src/arch" --older-than 1d --bucket "no-such-bucket-$RUN_ID" --output json 2>/dev/null) || rc=$?
	assert_eq "--bucket доходит до хранилища (failed=1)" "$(stat_field "$out" failed)" "1"
	assert_eq "--bucket на несуществующем бакете -> exit 1" "$rc" "1"

	# --workers: конкурентность влияет только на скорость, но флаг обязан
	# приниматься и не ломать счётчики.
	out=$(vault archive "$src/arch" --older-than 1d --workers 2 --prefix "w2-$RUN_ID" --output json 2>/dev/null)
	assert_eq "--workers 2: uploaded=1" "$(stat_field "$out" uploaded)" "1"
	assert_ok "--workers 2 положил объект" s3_head_raw "w2-$RUN_ID/hello.txt"

	vault download "$PREFIX/hello.txt" "$WORK/out-cli.bin"
	assert_same_bytes "download совпадает с исходником" "$src/arch/hello.txt" "$WORK/out-cli.bin"
	assert_eq "download в stdout" "$(vault download "$PREFIX/hello.txt" - 2>/dev/null)" "s3vault e2e payload"

	# Контейнер: магия S3VCTR01 + 128-байтовый заголовок перед payload.
	s3_get_raw "$PREFIX/hello.txt" "$WORK/raw-cli.bin"
	assert_eq "S3VCTR01 в теле объекта" "$(head -c 8 "$WORK/raw-cli.bin")" "S3VCTR01"
	assert_eq "размер объекта = 128 + payload" \
		"$(wc -c <"$WORK/raw-cli.bin")" "$((128 + $(wc -c <"$src/arch/hello.txt")))"

	# --- перезапись по ключу: один ключ, меняющееся содержимое ---
	printf 'single upload\n' >"$src/pol/one.txt"
	out=$(vault upload "$src/pol/one.txt" --key pol/one.txt --output json 2>/dev/null)
	assert_eq "upload --key: uploaded=1" "$(stat_field "$out" uploaded)" "1"
	assert_ok "upload --key создал объект" s3_head_raw "$PREFIX/pol/one.txt"

	# Другой контент под тем же ключом: перезаписываем (archive.on_change удалён,
	# политики «не писать» больше нет — см. problems.md H2).
	printf 'changed content\n' >"$src/pol/one.txt"
	out=$(vault upload "$src/pol/one.txt" --key pol/one.txt --output json 2>/dev/null)
	assert_eq "изменившийся контент: uploaded=1" "$(stat_field "$out" uploaded)" "1"
	assert_eq "объект перезаписан" \
		"$(vault download "$PREFIX/pol/one.txt" - 2>/dev/null)" "changed content"

	# Тот же контент: content-skip, локальный файл остаётся (delete-if-exists снимет).
	out=$(vault upload "$src/pol/one.txt" --key pol/one.txt --output json 2>/dev/null)
	assert_eq "тот же контент: skipped=1" "$(stat_field "$out" skipped)" "1"

	# Ключ настроек удалён — старт обязан упасть, а не молча сменить поведение.
	local rc=0
	S3VAULT_ARCHIVE_ON_CHANGE=skip vault upload "$src/pol/one.txt" \
		--key pol/one.txt >/dev/null 2>&1 || rc=$?
	assert_ne "archive.on_change отвергается на старте" "$rc" "0"

	# delete-after-upload / delete-if-exists.
	printf 'to be deleted\n' >"$src/pol/gone.txt"
	out=$(vault upload "$src/pol/gone.txt" --key pol/gone.txt --delete-after-upload --output json 2>/dev/null)
	assert_eq "delete-after-upload: uploaded=1" "$(stat_field "$out" uploaded)" "1"
	assert_fails "delete-after-upload удалил локальный файл" test -f "$src/pol/gone.txt"

	printf 'keep on skip\n' >"$src/pol/keep.txt"
	vault upload "$src/pol/keep.txt" --key pol/keep.txt >/dev/null 2>&1
	out=$(vault upload "$src/pol/keep.txt" --key pol/keep.txt --delete-if-exists --output json 2>/dev/null)
	assert_eq "delete-if-exists: skip=1" "$(stat_field "$out" skipped)" "1"
	assert_fails "delete-if-exists удалил локальный файл" test -f "$src/pol/keep.txt"

	printf 'stay put\n' >"$src/pol/stay.txt"
	vault upload "$src/pol/stay.txt" --key pol/stay.txt >/dev/null 2>&1
	assert_ok "без флагов локальный файл сохранён" test -f "$src/pol/stay.txt"

	# Симлинки в отдельном каталоге: по умолчанию пропускаются, --follow-symlinks включает.
	printf 'link target\n' >"$src/link/real.txt"
	touch -d '2020-01-01T00:00:00Z' "$src/link/real.txt"
	ln -sf real.txt "$src/link/link.txt"
	out=$(vault archive "$src/link" --older-than 1d --output json 2>/dev/null)
	assert_eq "симлинк пропущен по умолчанию (found=1)" "$(stat_field "$out" found)" "1"
	out=$(vault S3VAULT_ARCHIVE_FOLLOW_SYMLINKS=true archive "$src/link" \
		--older-than 1d --output json 2>/dev/null)
	assert_eq "follow_symlinks=true находит симлинк (found=2)" "$(stat_field "$out" found)" "2"

	# Multipart: manager.Uploader режет на части по 5 MiB, 12 MiB -> 3 части.
	head -c 12582912 /dev/urandom >"$src/multipart/big.bin"
	out=$(vault upload "$src/multipart/big.bin" --key multipart/big.bin --output json 2>/dev/null)
	assert_eq "multipart upload: uploaded=1" "$(stat_field "$out" uploaded)" "1"
	vault download "$PREFIX/multipart/big.bin" "$WORK/out-multipart.bin"
	assert_same_bytes "multipart roundtrip 12 MiB" "$src/multipart/big.bin" "$WORK/out-multipart.bin"

	# --metrics-listen живёт только на время прогона, поэтому снимаем экспорт
	# конкурентно. Чтобы окно не проскочить, гоняем 60 MiB свежих данных.
	# mtime обязателен: дефолт archive.older_than=7d отфильтровал бы свежие файлы,
	# и прогон завершился бы мгновенно, не дав снять метрики.
	local mport=19091 scraped="" mpid
	mkdir -p "$src/metrics"
	local i
	for i in 1 2 3 4 5 6; do
		head -c 10485760 /dev/urandom >"$src/metrics/chunk-$i.bin"
		touch -d '2020-01-01T00:00:00Z' "$src/metrics/chunk-$i.bin"
	done
	vault archive "$src/metrics" --older-than 1d --metrics-listen "127.0.0.1:$mport" >/dev/null 2>&1 &
	mpid=$!
	for _ in $(seq 1 2000); do
		scraped=$(curl -fsS --max-time 1 "http://127.0.0.1:$mport/metrics" 2>/dev/null) && break
		kill -0 "$mpid" 2>/dev/null || break
	done
	wait "$mpid" || true
	assert_contains "--metrics-listen отдаёт s3vault_files_total" "$scraped" "s3vault_files_total"

	# Несуществующий ключ: ненулевой код и никакого частичного файла.
	rc=0
	vault download "$PREFIX/does-not-exist" "$WORK/nope.bin" >/dev/null 2>&1 || rc=$?
	assert_ne "download несуществующего ключа падает" "$rc" "0"
	assert_fails "частичный файл не остался" test -f "$WORK/nope.bin"
}

# --------------------------------------------------------------- encrypt ---

phase_encrypt() {
	log "Режимы шифрования: none / native rsa-oaep / native keyfile / command"
	wait_minio
	local src="$WORK/src-enc"
	rm -rf "$src"
	mkdir -p "$src"

	local pub="$WORK/rsa_pub.pem" prv="$WORK/rsa_priv.pem" kek="$WORK/kek.bin"
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$prv" 2>/dev/null
	openssl rsa -in "$prv" -pubout -out "$pub" 2>/dev/null
	head -c 32 /dev/urandom >"$kek"

	local native_rsa=(S3VAULT_ENCRYPTION_MODE=native S3VAULT_ENCRYPTION_NATIVE_WRAP=rsa-oaep
		S3VAULT_ENCRYPTION_NATIVE_PUBLIC_KEY_PATH="$pub" S3VAULT_ENCRYPTION_NATIVE_PRIVATE_KEY_PATH="$prv")
	local native_kek=(S3VAULT_ENCRYPTION_MODE=native S3VAULT_ENCRYPTION_NATIVE_WRAP=keyfile
		S3VAULT_ENCRYPTION_NATIVE_KEY_FILE="$kek")

	# --- native rsa-oaep ---
	printf 'rsa payload\n' >"$src/rsa.txt"
	touch -d '2020-01-01T00:00:00Z' "$src/rsa.txt"
	vault "${native_rsa[@]}" upload "$src/rsa.txt" --key enc/rsa.txt >/dev/null
	vault "${native_rsa[@]}" download "$PREFIX/enc/rsa.txt" "$WORK/enc-rsa.out"
	assert_same_bytes "native rsa-oaep roundtrip" "$src/rsa.txt" "$WORK/enc-rsa.out"

	# Формат native — S3VCTR01 || S3VLT01 || chunks: магия контейнера в 0,
	# магия шифротекста — сразу за 128-байтовым заголовком (architecture.md).
	s3_get_raw "$PREFIX/enc/rsa.txt" "$WORK/enc-rsa.raw"
	assert_eq "native: контейнер S3VCTR01 в начале объекта" \
		"$(head -c 8 "$WORK/enc-rsa.raw")" "S3VCTR01"
	assert_eq "native: S3VLT01 по смещению 128" \
		"$(dd if="$WORK/enc-rsa.raw" bs=1 skip=128 count=7 2>/dev/null)" "S3VLT01"

	# Режим none обязан честно отказаться, а не выдать мусор.
	local rc=0 msg
	msg=$(vault download "$PREFIX/enc/rsa.txt" "$WORK/enc-rsa-none.out" 2>&1) || rc=$?
	assert_ne "native-объект не читается в mode=none" "$rc" "0"
	assert_contains "mode=none объясняет причину" "$msg" "requires encryption.mode=native"

	# --- native keyfile ---
	printf 'kek payload\n' >"$src/kek.txt"
	touch -d '2020-01-01T00:00:00Z' "$src/kek.txt"
	vault "${native_kek[@]}" upload "$src/kek.txt" --key enc/kek.txt >/dev/null
	vault "${native_kek[@]}" download "$PREFIX/enc/kek.txt" "$WORK/enc-kek.out"
	assert_same_bytes "native keyfile roundtrip" "$src/kek.txt" "$WORK/enc-kek.out"

	# Неверный KEK обязан упасть на аутентификации AEAD.
	head -c 32 /dev/urandom >"$WORK/kek-wrong.bin"
	rc=0
	vault S3VAULT_ENCRYPTION_MODE=native S3VAULT_ENCRYPTION_NATIVE_WRAP=keyfile \
		S3VAULT_ENCRYPTION_NATIVE_KEY_FILE="$WORK/kek-wrong.bin" \
		download "$PREFIX/enc/kek.txt" "$WORK/enc-kek-wrong.out" >/dev/null 2>&1 || rc=$?
	assert_ne "неверный KEK не расшифровывает" "$rc" "0"
	assert_fails "битая расшифровка не оставила файл" test -f "$WORK/enc-kek-wrong.out"

	# --- command (подмена cryptcp) ---
	# argv-списки не биндятся из env (см. .env.example), поэтому конфиг в YAML.
	local cfg="$WORK/command.yaml"
	cat >"$cfg" <<YAML
encryption:
  mode: command
  command:
    provider: cryptopro
    thumbprint: afa43c43975fbfc700f051fd62016e1571e7e025
    encrypt: ["$ROOT/scripts/cryptcp-encrypt"]
    decrypt: ["$ROOT/scripts/cryptcp-decrypt"]
    timeout: 5m
YAML

	printf 'gost-ish payload\n' >"$src/cmd.txt"
	touch -d '2020-01-01T00:00:00Z' "$src/cmd.txt"

	local fake=(CRYPTCP="$FAKE_CRYPTCP" E2E_FAKE_KEK="$kek" CRYPTOPRO_PIN=1234)
	vault "${fake[@]}" --config "$cfg" upload "$src/cmd.txt" --key enc/cmd.txt >/dev/null
	vault "${fake[@]}" --config "$cfg" download "$PREFIX/enc/cmd.txt" "$WORK/enc-cmd.out"
	assert_same_bytes "command-режим roundtrip через cryptcp" "$src/cmd.txt" "$WORK/enc-cmd.out"

	# S3VCTR01 хранит thumbprint: download берёт его из заголовка, поэтому смена
	# ключа в конфиге не ломает чтение старых объектов (заявлено в README).
	# Присваивания окружения обязаны идти ПЕРЕД флагами: vault() разбирает
	# только ведущие VAR=VAL, всё остальное считает аргументами CLI.
	vault "${fake[@]}" S3VAULT_ENCRYPTION_COMMAND_THUMBPRINT=1111111111111111111111111111111111111111 \
		--config "$cfg" download "$PREFIX/enc/cmd.txt" "$WORK/enc-cmd-rot.out" >/dev/null
	assert_same_bytes "thumbprint взят из S3VCTR01, а не из конфига" "$src/cmd.txt" "$WORK/enc-cmd-rot.out"

	# Настоящая проверка проброса ключевого материала: другой контейнер — другой ключ.
	head -c 32 /dev/urandom >"$WORK/kek-other.bin"
	local rc=0
	vault CRYPTCP="$FAKE_CRYPTCP" E2E_FAKE_KEK="$WORK/kek-other.bin" CRYPTOPRO_PIN=1234 \
		--config "$cfg" download "$PREFIX/enc/cmd.txt" "$WORK/enc-cmd-bad.out" >/dev/null 2>&1 || rc=$?
	assert_ne "чужой контейнер не расшифровывает объект" "$rc" "0"
}

# ---------------------------------------------------------------- server ---

phase_server() {
	log "HTTP-сервер: health/ready, метрики, graceful shutdown; plaintext через S3-фасад"
	wait_minio
	local src="$WORK/src-srv"
	rm -rf "$src"
	mkdir -p "$src/srv"
	printf 'server payload\n' >"$src/srv/app.log"
	touch -d '2020-01-01T00:00:00Z' "$src/srv/app.log"
	vault upload "$src/srv/app.log" --key srv/app.log >/dev/null 2>&1

	start_vault || return

	# /files удалён: HTTP-слушатель несёт только health/ready без аутентификации.
	assert_eq "/health" "$(curl -fsS "$HTTP_URL/health")" "ok"
	assert_eq "/ready (S3 доступен)" "$(curl -fsS "$HTTP_URL/ready")" "ok"

	# plaintext, Range и ETag читаются через S3-фасад (SigV4).
	assert_eq "S3-facade GetObject отдаёт plaintext" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" "$S3API_URL/$S3_BUCKET/srv/app.log")" \
		"server payload"
	assert_eq "S3-facade Range bytes=0-5" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" -H 'Range: bytes=0-5' "$S3API_URL/$S3_BUCKET/srv/app.log")" \
		"server"
	assert_eq "S3-facade ETag = sha256(plaintext) в кавычках" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" -I "$S3API_URL/$S3_BUCKET/srv/app.log" |
			tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}')" \
		"\"$(sha256_hex "$src/srv/app.log")\""

	# Метрики.
	local metrics
	metrics=$(curl -fsS "$METRICS_URL/metrics" 2>/dev/null || true)
	assert_contains "s3vault_http_requests_total" "$metrics" "s3vault_http_requests_total"
	assert_contains "s3vault_files_total" "$metrics" "s3vault_files_total"
	assert_contains "runtime go metrics" "$metrics" "go_goroutines"
	assert_not_contains "cache.enabled=false: gauge кэша нет" "$metrics" "s3vault_cache_entries"

	# Graceful shutdown: SIGTERM -> exit 0.
	local rc=0
	stop_vault || rc=$?
	assert_eq "SIGTERM: graceful shutdown, exit 0" "$rc" "0"
	assert_ok "порт освобождён" bash -c "! curl -fsS --max-time 1 $HTTP_URL/health"

	# Кэш включён: запись на диск, cache stats, cache clear.
	# cache stats обязан видеть тот же cache.dir, что и сервер, — иначе он
	# отчитается о дефолтном ~/.cache/s3vault и покажет ноль записей.
	local cachenv=(S3VAULT_CACHE_ENABLED=true S3VAULT_CACHE_DIR="$WORK/cache")
	rm -rf "$WORK/cache"
	start_vault "${cachenv[@]}" S3VAULT_CACHE_SOFT_TTL=20s || return
	sigv4 "$FACADE_AK" "$FACADE_SK" "$S3API_URL/$S3_BUCKET/srv/app.log" >/dev/null
	local stats
	stats=$(vault "${cachenv[@]}" cache stats 2>/dev/null)
	assert_contains "cache stats: entries=1" "$stats" "entries=1"
	assert_contains "cache stats печатает dir" "$stats" "dir=$WORK/cache"
	assert_eq "второй GET из кэша — тот же plaintext" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" "$S3API_URL/$S3_BUCKET/srv/app.log")" "server payload"
	local metrics2
	metrics2=$(curl -fsS "$METRICS_URL/metrics" 2>/dev/null || true)
	assert_contains "gauge кэша появился" "$metrics2" "s3vault_cache_entries"
	assert_contains "cache hit зафиксирован" "$metrics2" "s3vault_cache_hits_total"
	assert_eq "cache clear" "$(vault "${cachenv[@]}" cache clear 2>/dev/null)" "cache cleared"
	assert_contains "cache stats после clear пуст" \
		"$(vault "${cachenv[@]}" cache stats 2>/dev/null)" "entries=0"
	stop_vault || true
}

# ---------------------------------------------------------------- facade ---

sigv4() { # sigv4 <ak> <sk> [curl args...]
	local ak=$1 sk=$2
	shift 2
	curl -sS --aws-sigv4 "aws:amz:${REGION}:s3" --user "${ak}:${sk}" "$@"
}

phase_facade() {
	log "SigV4 S3-фасад: bucket/object/list/range/checksum/ACL"
	wait_minio
	start_vault || return

	assert_contains "ListBuckets отдаёт виртуальный бакет" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" "$S3API_URL/")" "<Name>${S3_BUCKET}</Name>"
	assert_eq "HeadBucket -> 200" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" -o /dev/null -w '%{http_code}' -I "$S3API_URL/$S3_BUCKET")" "200"

	local obj="$WORK/facade.txt"
	printf 'facade payload\n' >"$obj"

	assert_eq "PutObject -> 200" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" -o /dev/null -w '%{http_code}' -X PUT \
			--data-binary "@$obj" "$S3API_URL/$S3_BUCKET/facade/f.txt")" "200"
	assert_ok "объект ушёл в S3" s3_head_raw "$PREFIX/facade/f.txt"
	assert_eq "GetObject отдаёт plaintext" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" "$S3API_URL/$S3_BUCKET/facade/f.txt")" "facade payload"
	assert_eq "Range GetObject (bytes=0-6, 7 байт)" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" -H 'Range: bytes=0-6' "$S3API_URL/$S3_BUCKET/facade/f.txt")" "facade "
	assert_eq "HeadObject -> 200" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" -o /dev/null -w '%{http_code}' -I "$S3API_URL/$S3_BUCKET/facade/f.txt")" "200"

	# x-amz-checksum-sha256 = base64(sha256(plaintext)).
	local want_sum got_sum
	want_sum=$(openssl dgst -sha256 -binary "$obj" | openssl base64 -A)
	got_sum=$(sigv4 "$FACADE_AK" "$FACADE_SK" -I "$S3API_URL/$S3_BUCKET/facade/f.txt" |
		tr -d '\r' | awk -F': ' 'tolower($1)=="x-amz-checksum-sha256"{print $2}')
	assert_eq "x-amz-checksum-sha256 = base64(sha256(plaintext))" "$got_sum" "$want_sum"

	# Префикс в запросе — в пользовательском пространстве ("facade/"), серверный
	# S3-префикс фасад подставляет сам. <Key> тоже приходит уже без него.
	assert_contains "ListObjectsV2 находит ключ" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" "$S3API_URL/$S3_BUCKET?list-type=2&prefix=facade/")" \
		"<Key>facade/f.txt</Key>"

	assert_eq "DeleteObject -> 204" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" -o /dev/null -w '%{http_code}' -X DELETE \
			"$S3API_URL/$S3_BUCKET/facade/f.txt")" "204"
	assert_fails "объекта больше нет в S3" s3_head_raw "$PREFIX/facade/f.txt"

	# Авторизация.
	assert_eq "неверная подпись -> 403" \
		"$(sigv4 "$FACADE_AK" "wrong-secret" -o /dev/null -w '%{http_code}' "$S3API_URL/$S3_BUCKET/facade/f.txt")" "403"
	assert_eq "чужой access key -> 403" \
		"$(sigv4 "someone-else" "$FACADE_SK" -o /dev/null -w '%{http_code}' "$S3API_URL/$S3_BUCKET/facade/f.txt")" "403"
	assert_eq "чужой бакет -> 403" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" -o /dev/null -w '%{http_code}' "$S3API_URL/not-my-bucket/facade/f.txt")" "403"

	# Обход пути в ключе отвергается (filepath.IsLocal в keying).
	assert_ne "S3-ключ с .. не отдаёт 200" \
		"$(sigv4 "$FACADE_AK" "$FACADE_SK" -o /dev/null -w '%{http_code}' \
			--path-as-is "$S3API_URL/$S3_BUCKET/../../etc/passwd")" "200"

	# S3-метрика живёт в фасаде, а не в /files: это CounterVec, и без
	# S3-шлюзовых запросов она просто не экспортируется.
	local fmetrics
	fmetrics=$(curl -fsS "$METRICS_URL/metrics" 2>/dev/null || true)
	assert_contains "s3vault_s3_requests_total после S3-запросов" \
		"$fmetrics" "s3vault_s3_requests_total"

	# Настоящий AWS-клиент поверх того же фасада.
	printf 'from aws cli\n' >"$obj"
	AWS_ACCESS_KEY_ID="$FACADE_AK" AWS_SECRET_ACCESS_KEY="$FACADE_SK" \
		aws --endpoint-url "$S3API_URL" s3api put-object --bucket "$S3_BUCKET" \
		--key facade/aws.txt --body "$obj" >/dev/null
	AWS_ACCESS_KEY_ID="$FACADE_AK" AWS_SECRET_ACCESS_KEY="$FACADE_SK" \
		aws --endpoint-url "$S3API_URL" s3api get-object --bucket "$S3_BUCKET" \
		--key facade/aws.txt "$WORK/facade-aws.out" >/dev/null
	assert_same_bytes "aws s3api roundtrip через фасад" "$obj" "$WORK/facade-aws.out"

	stop_vault || true
}

# ---------------------------------------------------------------- local ---

phase_local() {
	log "Локальный бэкенд: container и raw (MinIO не нужен)"
	local src="$WORK/src-local"
	rm -rf "$src"
	mkdir -p "$src/loc"
	printf 'local payload\n' >"$src/loc/a.txt"
	touch -d '2020-01-01T00:00:00Z' "$src/loc/a.txt"
	head -c 32 /dev/urandom >"$WORK/kek-local.bin"

	local container="$WORK/store-container" raw="$WORK/store-raw" rc=0 out
	rm -rf "$container" "$raw"
	local base=(S3VAULT_BACKEND_TYPE=local S3VAULT_S3_ENDPOINT=)

	# container — S3VCTR01 || payload, как в S3.
	out=$(vault "${base[@]}" S3VAULT_BACKEND_LOCAL_DIR="$container" \
		upload "$src/loc/a.txt" --key loc/a.txt --output json 2>/dev/null)
	assert_eq "local container: uploaded=1" "$(stat_field "$out" uploaded)" "1"
	assert_eq "local container: магия S3VCTR01" "$(head -c 8 "$container/$PREFIX/loc/a.txt")" "S3VCTR01"

	out=$(vault "${base[@]}" S3VAULT_BACKEND_LOCAL_DIR="$container" \
		upload "$src/loc/a.txt" --key loc/a.txt --output json 2>/dev/null)
	assert_eq "local container: повтор -> skipped=1" "$(stat_field "$out" skipped)" "1"

	vault "${base[@]}" S3VAULT_BACKEND_LOCAL_DIR="$container" \
		download "$PREFIX/loc/a.txt" "$WORK/local-container.out"
	assert_same_bytes "local container roundtrip" "$src/loc/a.txt" "$WORK/local-container.out"

	# raw (mode=none) — payload без контейнера, чистый plaintext.
	out=$(vault "${base[@]}" S3VAULT_BACKEND_LOCAL_DIR="$raw" S3VAULT_BACKEND_LOCAL_LAYOUT=raw \
		upload "$src/loc/a.txt" --key loc/a.txt --output json 2>/dev/null)
	assert_eq "local raw: uploaded=1" "$(stat_field "$out" uploaded)" "1"
	assert_eq "local raw: файл = plaintext без заголовка" "$(cat "$raw/$PREFIX/loc/a.txt")" "local payload"

	vault "${base[@]}" S3VAULT_BACKEND_LOCAL_DIR="$raw" S3VAULT_BACKEND_LOCAL_LAYOUT=raw \
		download "$PREFIX/loc/a.txt" "$WORK/local-raw.out"
	assert_same_bytes "local raw roundtrip" "$src/loc/a.txt" "$WORK/local-raw.out"

	# raw + шифрование отвергается на старте: raw не несёт заголовок S3VCTR01,
	# поэтому enc-маркера нет и детектор не отличит шифртекст от plaintext.
	rc=0
	vault "${base[@]}" S3VAULT_BACKEND_LOCAL_DIR="$raw" S3VAULT_BACKEND_LOCAL_LAYOUT=raw \
		S3VAULT_ENCRYPTION_MODE=native S3VAULT_ENCRYPTION_NATIVE_WRAP=keyfile \
		S3VAULT_ENCRYPTION_NATIVE_KEY_FILE="$WORK/kek-local.bin" \
		upload "$src/loc/a.txt" --key loc/enc.txt >/dev/null 2>&1 || rc=$?
	assert_ne "local raw + native отвергается" "$rc" "0"

	# Локальный бэкенд без dir.
	rc=0
	vault S3VAULT_BACKEND_TYPE=local S3VAULT_BACKEND_LOCAL_DIR= S3VAULT_S3_ENDPOINT= \
		upload "$src/loc/a.txt" >/dev/null 2>&1 || rc=$?
	assert_ne "local без dir отвергается" "$rc" "0"
}

# ----------------------------------------------------------- resilience ---

phase_resilience() {
	log "Отказоустойчивость: битый объект, прерванная загрузка, cache stampede, S3 недоступен"
	wait_minio
	local src="$WORK/src-res"
	rm -rf "$src"
	mkdir -p "$src/agefail"

	# Четыре файла для проверок archive против мёртвого S3 и --fail-fast.
	local i
	for i in 1 2 3 4; do
		printf 'agefail %s\n' "$i" >"$src/agefail/f$i.txt"
		touch -d '2020-01-01T00:00:00Z' "$src/agefail/f$i.txt"
	done

	# --- битый шифротекст: заголовок цел, AEAD-аутентификация обязана сорваться ---
	head -c 32 /dev/urandom >"$WORK/kek-res.bin"
	local enc=(S3VAULT_ENCRYPTION_MODE=native S3VAULT_ENCRYPTION_NATIVE_WRAP=keyfile
		S3VAULT_ENCRYPTION_NATIVE_KEY_FILE="$WORK/kek-res.bin")
	printf 'corrupt me\n' >"$src/corrupt.bin"
	touch -d '2020-01-01T00:00:00Z' "$src/corrupt.bin"
	vault "${enc[@]}" upload "$src/corrupt.bin" --key res/corrupt.bin >/dev/null

	s3_get_raw "$PREFIX/res/corrupt.bin" "$WORK/corrupt.raw"
	# Портим последний байт — это AEAD-тег; заголовок S3VCTR01 (128 Б) не тронут.
	local size
	size=$(wc -c <"$WORK/corrupt.raw")
	printf '\xff' | dd of="$WORK/corrupt.raw" bs=1 seek=$((size - 1)) count=1 conv=notrunc 2>/dev/null
	s3_put_raw "$PREFIX/res/corrupt.bin" "$WORK/corrupt.raw"

	local rc=0
	vault "${enc[@]}" download "$PREFIX/res/corrupt.bin" "$WORK/corrupt.out" >/dev/null 2>&1 || rc=$?
	assert_ne "битый шифротекст: download падает" "$rc" "0"
	assert_fails "битый объект не оставил файл" test -f "$WORK/corrupt.out"

	# Идентичность живёт в CRC-заголовке S3VCTR01, а тело при Head не читается,
	# поэтому archive повреждённый объект пропускает как «идентичный» (так и в
	# architecture.md: смена ключа при том же plaintext не перезаливает).
	# Порчу ловит только download — и это надо зафиксировать, а не лечить тут.
	local out
	out=$(vault "${enc[@]}" upload "$src/corrupt.bin" --key res/corrupt.bin --output json 2>/dev/null)
	assert_eq "archive пропускает объект по заголовку, не читая тело" \
		"$(stat_field "$out" uploaded)/$(stat_field "$out" skipped)" "0/1"
	rc=0
	vault "${enc[@]}" download "$PREFIX/res/corrupt.bin" "$WORK/corrupt-again.out" >/dev/null 2>&1 || rc=$?
	assert_ne "повторный download всё ещё падает" "$rc" "0"

	# --- прерванная загрузка: dest появляется только целиком (temp + rename) ---
	local big=134217728
	head -c "$big" /dev/urandom >"$src/huge.bin"
	touch -d '2020-01-01T00:00:00Z' "$src/huge.bin"
	vault upload "$src/huge.bin" --key res/huge.bin >/dev/null
	local destdir="$WORK/dl"
	rm -rf "$destdir"
	mkdir -p "$destdir"
	vault download "$PREFIX/res/huge.bin" "$destdir/huge.bin" >/dev/null 2>&1 &
	local dl_pid=$! saw_partial=0
	for _ in $(seq 1 300); do
		if [[ -e "$destdir/huge.bin" ]]; then saw_partial=1; break; fi
		kill -0 "$dl_pid" 2>/dev/null || break
		sleep 0.01
	done
	if [[ $saw_partial -eq 1 ]]; then
		local partial_size
		partial_size=$(wc -c <"$destdir/huge.bin")
		if [[ $partial_size -eq $big ]]; then
			pass "прерванная загрузка: dest появился только целиком ($partial_size Б)"
		else
			fail "прерванная загрузка: dest появился на $partial_size Б из $big"
		fi
	else
		pass "прерванная загрузка: dest не появился до завершения"
	fi
	wait "$dl_pid" || fail "download 128 MiB не завершился"
	assert_same_bytes "128 MiB скачался целиком" "$src/huge.bin" "$destdir/huge.bin"
	assert_eq "временных файлов не осталось" "$(find "$destdir" -name '.s3vault-*' | wc -l)" "0"
	rm -f "$src/huge.bin" "$destdir/huge.bin"

	# --- cache stampede: N параллельных холодных GET на один ключ ---
	printf 'stampede payload\n' >"$src/stampede.log"
	touch -d '2020-01-01T00:00:00Z' "$src/stampede.log"
	vault upload "$src/stampede.log" --key srv/stampede.log >/dev/null
	rm -rf "$WORK/cache-stampede" "$WORK/stampede"
	mkdir -p "$WORK/stampede"
	start_vault S3VAULT_CACHE_ENABLED=true S3VAULT_CACHE_DIR="$WORK/cache-stampede" \
		S3VAULT_CACHE_SOFT_TTL=1m || return
	# Ждём именно curl-ы по pid: голый wait пере-reap'ит и s3vault-сервер,
	# после чего stop_vault не может дождаться его кода выхода.
	local n cpid
	local -a cpids=()
	for n in $(seq 1 16); do
		sigv4 "$FACADE_AK" "$FACADE_SK" "$S3API_URL/$S3_BUCKET/srv/stampede.log" \
			>"$WORK/stampede/$n" &
		cpids+=("$!")
	done
	for cpid in "${cpids[@]}"; do wait "$cpid" || fail "параллельный GET #$cpid упал"; done
	local mismatched=0
	for n in $(seq 1 16); do
		cmp -s "$WORK/stampede/$n" "$src/stampede.log" || mismatched=$((mismatched + 1))
	done
	assert_eq "16 параллельных GET вернули одинаковый plaintext" "$mismatched" "0"
	local entries
	entries=$(curl -fsS "$METRICS_URL/metrics" | awk '/^s3vault_cache_entries /{print $2}')
	assert_eq "в кэше ровно одна запись (singleflight + lockfile)" "$entries" "1"
	stop_vault || true

	# --- S3 недоступен ---
	# Отказ имитируем управляемым TCP-прокси, а не docker compose stop: так фаза
	# не зависит от прав на Docker и работает против MinIO, поднятого снаружи.
	log "S3 недоступен: рвём прокси до MinIO"
	local proxy_port=19099
	proxy_up "$proxy_port" || return
	assert_ok "прокси на $proxy_port отвечает" curl -fsS "http://127.0.0.1:$proxy_port/minio/health/ready"
	proxy_down

	printf 'during outage\n' >"$src/outage.txt"
	touch -d '2020-01-01T00:00:00Z' "$src/outage.txt"
	rc=0
	vault S3VAULT_S3_ENDPOINT="http://127.0.0.1:$proxy_port" \
		upload "$src/outage.txt" --key res/outage.txt >/dev/null 2>&1 || rc=$?
	assert_ne "upload при недоступном S3 падает" "$rc" "0"
	assert_fails "объект не создан" s3_head_raw "$PREFIX/res/outage.txt"

	# archive против мёртвого S3: это другой путь кода, чем upload — тут
	# ошибка на каждый файл своя, и Run возвращает ErrPartialFailures, который
	# CLI превращает в ExitError{Code:1}. Проверяем именно код 1, а не "не ноль".
	local arc=0 aout
	aout=$(vault S3VAULT_S3_ENDPOINT="http://127.0.0.1:$proxy_port" \
		archive "$src/agefail" --older-than 1d --output json 2>/dev/null) || arc=$?
	assert_eq "archive при мёртвом S3 -> exit 1" "$arc" "1"
	assert_eq "archive при мёртвом S3 -> failed=4" "$(stat_field "$aout" failed)" "4"

	# --fail-fast обрывает обход на первой ошибке. Видно только при одном
	# воркере: при 4 все файлы уже в полёте и падают заподряд, счётчик не
	# отличим от прогона без флага.
	local ffc=0 ffout
	ffout=$(vault S3VAULT_S3_ENDPOINT="http://127.0.0.1:$proxy_port" \
		archive "$src/agefail" --older-than 1d --workers 1 --fail-fast --output json 2>/dev/null) || ffc=$?
	assert_eq "--fail-fast против мёртвого S3 -> exit 1" "$ffc" "1"
	assert_lt "--fail-fast обрывает обход до 4 файлов" "$(stat_field "$ffout" failed)" "4"

	# Тот же обход с 4 воркерами: файлы уже в полёте, поэтому --fail-fast не
	# успевает сработать и отказов снова 4. Разница с предыдущей строкой
	# доказывает, что --workers доходит до конкурентности, а не игнорируется.
	local w4out
	w4out=$(vault S3VAULT_S3_ENDPOINT="http://127.0.0.1:$proxy_port" \
		archive "$src/agefail" --older-than 1d --workers 4 --fail-fast --output json 2>/dev/null) || true
	assert_eq "--workers 4 не даёт --fail-fast оборваться (failed=4)" \
		"$(stat_field "$w4out" failed)" "4"

	# Сервер остаётся живым и честно отвечает ошибкой, а не 200 с мусором.
	# nowait не ждёт готовности (S3 мёртв), но /health от S3 не зависит,
	# поэтому ждём именно его — иначе curl упирается в гонку с биндингом порта.
	start_vault nowait S3VAULT_S3_ENDPOINT="http://127.0.0.1:$proxy_port" || return
	wait_for "/health при мёртвом S3" curl -fsS "$HTTP_URL/health" || return
	assert_eq "/health не зависит от S3" "$(curl -fsS "$HTTP_URL/health")" "ok"
	assert_status "/ready при мёртвом S3 -> 503" 503 \
		"$(curl -s -o /dev/null -w '%{http_code}' "$HTTP_URL/ready")"
	local filescode
	filescode=$(sigv4 "$FACADE_AK" "$FACADE_SK" -o /dev/null -w '%{http_code}' \
		"$S3API_URL/$S3_BUCKET/srv/app.log")
	assert_ne "S3-facade GetObject при мёртвом S3 не отдаёт 200" "$filescode" "200"
	stop_vault || true

	log "S3 возвращается"
	proxy_up "$proxy_port" || return
	wait_for "MinIO через прокси" curl -fsS "http://127.0.0.1:$proxy_port/minio/health/ready"
	out=$(vault S3VAULT_S3_ENDPOINT="http://127.0.0.1:$proxy_port" \
		upload "$src/outage.txt" --key res/outage.txt --output json 2>/dev/null)
	assert_eq "после восстановления upload проходит" "$(stat_field "$out" uploaded)" "1"
	vault S3VAULT_S3_ENDPOINT="http://127.0.0.1:$proxy_port" \
		download "$PREFIX/res/outage.txt" "$WORK/outage.out"
	assert_same_bytes "объект после восстановления читается" "$src/outage.txt" "$WORK/outage.out"
	proxy_down
}

# ------------------------------------------------------------------ main ---

# Фазам, которым не нужен MinIO, не ждём его и не требуем Docker.
phase_needs_s3() {
	case "$1" in
	local) return 1 ;;
	*) return 0 ;;
	esac
}

main() {
	local cmd="${1:-all}"
	CURRENT_PHASE="setup"

	case "$cmd" in
	up) phase_up; return $? ;;
	down) phase_down; return $? ;;
	clean) phase_down; rm -rf "$WORK"; log "стенд и $WORK удалены"; return 0 ;;
	build) build_vault; return $? ;;
	esac

	local phases
	case "$cmd" in
	all) phases=(go cli encrypt server facade local resilience) ;;
	go | cli | encrypt | server | facade | local | resilience) phases=("$cmd") ;;
	*)
		printf 'usage: %s [all|up|down|clean|build|go|cli|encrypt|server|facade|local|resilience]\n' "$0" >&2
		return 2
		;;
	esac

	build_vault

	# Стенд самодостаточен: если хоть одной фазе нужен S3, поднимаем MinIO один раз.
	local p needs_s3=0
	for p in "${phases[@]}"; do
		phase_needs_s3 "$p" && needs_s3=1
	done
	if [[ $needs_s3 -eq 1 ]]; then
		CURRENT_PHASE="minio"
		start_minio
	fi

	local started=$SECONDS
	for p in "${phases[@]}"; do
		CURRENT_PHASE="$p"
		phase_"$p"
		stop_vault >/dev/null 2>&1 || true
	done

	local color="$C_GREEN"
	[[ $FAILED -gt 0 ]] && color="$C_RED"
	printf '\n%s%d passed%s, %s%d failed%s in %ds\n' \
		"$C_GREEN" "$PASSED" "$C_OFF" "$color" "$FAILED" "$C_OFF" "$((SECONDS - started))"

	if [[ $FAILED -gt 0 ]]; then
		printf '\nПровалено:\n'
		printf '  - %s\n' "${FAILURES[@]}"
		return 1
	fi
	return 0
}

main "$@"
