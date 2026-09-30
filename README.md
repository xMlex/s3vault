# s3vault

Утилита на Go: находит локальные файлы старше заданного периода, загружает их в S3-совместимое хранилище или в локальную директорию, при необходимости шифрует на клиенте и скачивает уже в открытом виде.

Повторная загрузка того же содержимого пропускается по идентичности из заголовка объекта `S3VCTR01` (SHA-256 plaintext); ETag как хеш содержимого не используется. Legacy-объекты со старым `s3vault-*` user-metadata читаются как fallback, но новые Put его не пишут. После успешного upload локальный файл **не удаляется**, пока не указан `--delete-after-upload`. Если объект уже есть с тем же содержимым (skip) — `--delete-if-exists`.

Архитектура: [architecture.md](architecture.md). Известные расхождения с кодом: [problems.md](problems.md).

## Что уже есть и чего нет

Работает: `archive` (включая `--dry-run`), `upload`, `download`, `server` (S3 SigV4 API, `/health` + `/ready`), `cache stats|clear`, шифрование `none` / `native` / `command`, Prometheus-метрики (HTTP, S3 API, кэш, upload/download). Бэкенд хранения — S3 или локальная директория (`backend.type`).

Systemd-юнит есть в репозитории — `s3vault.service`, положить в `/etc/systemd/system/`. Ниже запуск бинарём. `Dockerfile` есть, см. «Образ» в разделе «Сборка».

## Сборка

Нужен Go 1.26+ (в `go.mod` зафиксирована версия языка, директивы `toolchain` нет — используйте установленный тулчейн).

```bash
git clone <repo>
cd s3vault
go build -ldflags "-X main.version=$(git describe --tags --always --dirty)" -o bin/s3vault ./cmd/s3vault
# или
make build
```

Проверки:

```bash
make test                                                    # go test -race -count=1 ./...
go vet ./...
gofmt -l .
golangci-lint run --new-from-rev=HEAD ./...                  # дерево не lint-clean: смотрите только свою дельту
go test -tags=integration -count=1 ./internal/integration/   # нужен доступ к S3, иначе skip; см. ниже
```

### Образ

```bash
docker build --build-arg VERSION=$(git describe --tags --always --dirty) -t s3vault .
```

Двухстадийная сборка: `golang:1.26-alpine` собирает статический бинарь (`CGO_ENABLED=0`), рантайм — `distroless/static-debian12:nonroot`, без shell и без libc.

Что стоит знать перед запуском:

- `server` по умолчанию слушает `127.0.0.1`, из контейнера это недостижимо, поэтому в образе задан `S3VAULT_SERVER_LISTEN=0.0.0.0:8080`. Сервер стартует только с ключами S3-фасада (`S3VAULT_SERVER_S3_ACCESS_KEY`/`S3VAULT_SERVER_S3_SECRET_KEY`), так что их придётся задать.
- Кэш выключен по умолчанию (`cache.enabled: false`) и не переживает перезапуск контейнера. Чтобы plaintext не терялся, смонтируйте том на `/cache` (`S3VAULT_CACHE_DIR=/cache`) — и держите в нём `0700`.
- `encryption.mode=command` из этого образа **не работает**: режим зовёт внешний `cryptcp`, которого в distroless нет. Берите `encryption.mode=native` либо свой образ с cryptcp.
- `encryption.mode=command` из этого образа **не работает**: режим зовёт внешний `cryptcp`, которого в distroless нет. Берите `encryption.mode=native` либо свой образ с cryptcp.
- Секреты в образ не запекаются: `.env`, `*.pem`, `kek.bin` перечислены в `.dockerignore`, конфигурация приходит через env или смонтированный файл.

## Быстрый старт: шлюз + архив

Сквозной сценарий целиком: файлы → клиент → шлюз → хранилище и обратно. Команды копируются как есть; порты по умолчанию — `8080` (`/health`, `/ready`), `8333` (S3-фасад), `9090` (метрики). Термины ниже — **хранилище**, **клиент**, **шлюз**, см. «Режимы работы».

```bash
make build                                        # ./s3vault

D=/tmp/demo; mkdir -p "$D/logs"                   # данные для архива
head -c 4096 /dev/urandom > "$D/logs/app.log"
printf 'hello from s3vault\n' > "$D/logs/notes.txt"
touch -d '10 days ago' "$D/logs/"*                # mtime старше 7 дней, иначе archive их не увидит

umask 077 && dd if=/dev/urandom of="$D/kek.bin" bs=32 count=1   # боевой путь — /etc/s3vault/kek.bin, 0600
```

### 1. Хранилище

```bash
docker compose -f compose.e2e.yaml up -d   # из корня репозитория: MinIO на :9000, бакет s3vault, креды s3vault/s3vaulttest
```

### 2. Шлюз

`S3VAULT_S3_*` — доступ шлюза к хранилищу, `S3VAULT_SERVER_S3_*` — ключи фасада, по которым с ним говорят клиенты. Шифрование — `native` с KEK, слой шлюза.

```bash
export S3VAULT_S3_ENDPOINT=http://127.0.0.1:9000
export S3VAULT_S3_REGION=us-east-1
export S3VAULT_S3_BUCKET=s3vault
export S3VAULT_S3_ACCESS_KEY=s3vault
export S3VAULT_S3_SECRET_KEY=s3vaulttest
export S3VAULT_S3_PATH_STYLE=true

export S3VAULT_ENCRYPTION_MODE=native
export S3VAULT_ENCRYPTION_NATIVE_WRAP=keyfile
export S3VAULT_ENCRYPTION_NATIVE_KEY_FILE="$D/kek.bin"

export S3VAULT_SERVER_S3_ACCESS_KEY=vaultak
export S3VAULT_SERVER_S3_SECRET_KEY=vaultsk
export S3VAULT_SERVER_S3_BUCKET=s3vault   # виртуальный бакет фасада

s3vault server --s3-listen 127.0.0.1:8333
```

Клиентский `S3VAULT_S3_BUCKET` обязан совпасть с виртуальным бакетом фасада, иначе `403 Forbidden` на первой же операции. Бакет шлюза по умолчанию равен его же `s3.bucket` (здесь `s3vault`), а при `S3VAULT_SERVER_S3_BUCKET_AS_PREFIX=true` подходит любое имя — оно становится префиксом ключа.

Ключи в этой схеме три, и их легко спутать, потому что все три живут в одном пространстве имён — `S3VAULT_S3_*`:

| пара | где задаётся | чья это пара |
| --- | --- | --- |
| креды хранилища | `S3VAULT_S3_ACCESS_KEY` / `S3VAULT_S3_SECRET_KEY` у шлюза | MinIO: `s3vault` / `s3vaulttest` |
| фронтенд шлюза | `S3VAULT_SERVER_S3_ACCESS_KEY` / `S3VAULT_SERVER_S3_SECRET_KEY` | свои; ими шлюз проверяет входящий SigV4 |
| креды клиента | `S3VAULT_S3_ACCESS_KEY` / `S3VAULT_S3_SECRET_KEY` у клиента | копия фронтенд-пары шлюза: `vaultak` / `vaultsk` |

Правило: `S3VAULT_S3_*` — это всегда «кем я являюсь для своего хранилища», а `S3VAULT_SERVER_S3_*` — «кем я пускаю к себе». Проверить, что пары разные, нечем, и задать их одинаковыми можно — тогда шлюз держит и ключи от себя, и ключи, которыми ходит в хранилище. В шагах 4 и 5 клиент намеренно меняет `S3VAULT_S3_*` на креды MinIO: то же место конфигурации, другой адресат.

### 3. Клиент архивирует через шлюз

Отдельный терминал. `s3.endpoint` теперь смотрит на шлюз, и S3-кредами клиента становятся фронтенд-ключи шлюза из шага 2 — не креды MinIO, а другая пара.

```bash
export S3VAULT_S3_ENDPOINT=http://127.0.0.1:8333
export S3VAULT_S3_BUCKET=s3vault
export S3VAULT_S3_ACCESS_KEY=vaultak
export S3VAULT_S3_SECRET_KEY=vaultsk
export S3VAULT_S3_PATH_STYLE=true
export S3VAULT_ENCRYPTION_MODE=native
export S3VAULT_ENCRYPTION_NATIVE_WRAP=keyfile
export S3VAULT_ENCRYPTION_NATIVE_KEY_FILE="$D/kek.bin"

s3vault archive "$D/logs" --older-than 7d --prefix demo --dry-run
s3vault archive "$D/logs" --older-than 7d --prefix demo
```

```text
level=INFO msg=file op=archive path=notes.txt key=demo/notes.txt size=19 dry_run=false
level=INFO msg=file op=archive path=app.log key=demo/app.log size=4096 dry_run=false
found=2 uploaded=2 skipped=0 failed=0 bytes_uploaded=4115 duration=14ms
```

Ключ объекта — `--prefix` клиента плюс путь относительно `/tmp/demo/logs`; `s3.prefix` шлюза пуст, поэтому общего корня сверху нет. Шифрование можно целиком отдать шлюзу (клиент с `encryption.mode=none` без CryptoPro) — см. топологию B.

### 4. Что видит хранилище

Один и тот же `notes.txt` (19 байт) — напрямую в хранилище и через шлюз:

```bash
# тот же файл мимо шлюза: 1 слой
S3VAULT_S3_ENDPOINT=http://127.0.0.1:9000 S3VAULT_S3_BUCKET=s3vault \
S3VAULT_S3_ACCESS_KEY=s3vault S3VAULT_S3_SECRET_KEY=s3vaulttest S3VAULT_S3_PATH_STYLE=true \
S3VAULT_ENCRYPTION_MODE=native S3VAULT_ENCRYPTION_NATIVE_WRAP=keyfile S3VAULT_ENCRYPTION_NATIVE_KEY_FILE="$D/kek.bin" \
  s3vault upload "$D/logs/notes.txt" --prefix demo-direct

AWS_ACCESS_KEY_ID=s3vault AWS_SECRET_ACCESS_KEY=s3vaulttest \
  aws --endpoint-url http://127.0.0.1:9000 s3 ls s3://s3vault/ --recursive
```

```text
2026-09-29 20:29:20        390 demo-direct/notes.txt
2026-09-29 20:29:20        761 demo/notes.txt
```

Лишние 371 байт — слой шлюза: ещё один контейнер `S3VCTR01` плюс конверт `S3VLT01`. **Вложенный слой в сырых байтах не виден**: шифротекст внешнего слоя лежит поверх всего объекта клиента, а не рядом с ним, поэтому подряд двух `S3VCTR01` в объекте не будет. Вложенность проверяется чтением.

### 5. Чтение: шлюз обязан быть и на пути чтения

```bash
s3vault download demo/notes.txt "$D/back.txt"      # тем же клиентским окружением
cmp "$D/logs/notes.txt" "$D/back.txt" && echo ok
```

`ok` — два процесса сняли по одному слою. Две типовые ошибки дают не мусор, а ровно «снят один слой»:

```bash
# мимо шлюза, прямо из хранилища: снят слой шлюза, шифротекст клиента остался
S3VAULT_S3_ENDPOINT=http://127.0.0.1:9000 S3VAULT_S3_BUCKET=s3vault \
S3VAULT_S3_ACCESS_KEY=s3vault S3VAULT_S3_SECRET_KEY=s3vaulttest \
  s3vault download demo/notes.txt "$D/direct.bin"   # 390 байт вместо 19
head -c 8 "$D/direct.bin"                           # S3VCTR01

# через фасад, но сторонним клиентом: снят слой шлюза, слой клиента — наружу
AWS_ACCESS_KEY_ID=vaultak AWS_SECRET_ACCESS_KEY=vaultsk \
  aws --endpoint-url http://127.0.0.1:8333 s3 cp s3://s3vault/demo/notes.txt "$D/aws.bin" \
  --region us-east-1                                 # тоже 390 байт, не plaintext
```

Оба файла — корректные объекты в один слой, просто не то, чего ждали. Для отдачи plaintext клиент должен идти в фасад тем же путём, каким шёл записью.

### 6. Повторный прогон, health, метрики

```bash
s3vault archive "$D/logs" --older-than 7d --prefix demo
# found=2 uploaded=0 skipped=2 failed=0 bytes_uploaded=0 duration=7ms

curl -fsS http://127.0.0.1:8080/health; echo   # ok
curl -fsS http://127.0.0.1:8080/ready; echo    # ok — дешёвый HEAD в хранилище
curl -s http://127.0.0.1:9090/metrics | grep s3vault_s3_requests_total
# s3vault_s3_requests_total{op="put",result="ok"} 2
```

Skip срабатывает по SHA-256 plaintext, а не по ETag, поэтому смена ключей сама по себе не перезаливает объект. Локальные файлы остаются на месте — убрать их можно только `--delete-after-upload`.

### 7. То же без Docker: хранилище в локальной директории

```bash
# шлюз: шифрование и ключи фасада из шага 2, вместо доступа в MinIO — директория
S3VAULT_BACKEND_TYPE=local S3VAULT_BACKEND_LOCAL_DIR="$D/objects" S3VAULT_S3_ENDPOINT= S3VAULT_S3_BUCKET= \
  s3vault server --s3-listen 127.0.0.1:8333

# клиент — как в шаге 3, меняется только S3VAULT_S3_ENDPOINT
find "$D/objects" -type f
```

Настоящий бакет не нужен: виртуальный бакет фасада тогда дефолтный (`s3vault`), слои и ключи ведут себя так же.

### 8. Уборка

```bash
docker compose -f compose.e2e.yaml down -v
rm -rf "$D"
```

## Режимы работы

В проекте три сущности. Путать их не надо — из этого путания растут почти все вопросы конфигурации.

| Сущность | Что это | Как задаётся |
| --- | --- | --- |
| **Хранилище** | Где физически лежат объекты: чужой S3/MinIO **или** локальная директория | `backend.type: s3 \| local` |
| **Клиент** | s3vault, который читает или пишет в хранилище. Своего хранилища у него нет | `archive`, `upload`, `download` |
| **Шлюз** | s3vault, у которого **тоже нет своего хранилища**: он стоит перед хранилищем, отдаёт plaintext и **сам является клиентом этого хранилища** | `s3vault server` |

Слово «server» в имени команды означает **шлюз**, а не хранилище. Сторонний S3-сервер в этих доках называется **хранилищем**. Ключа `role:` или `mode:` в конфиге нет и не нужно: роль задаётся командой, второго источника истины быть не должно.

Шлюз отдаёт наружу **один** фронтенд — **S3-фасад** (SigV4, для `aws-cli` и SDK). Обычный HTTP-слушатель несёт только `/health` и `/ready`. Bearer-фронтенд `HTTP /files` и режим `remote.url` удалены: и шлюз, и его клиенты говорят на одном протоколе — S3.

Ровно так же расходятся и ключи: `S3VAULT_SERVER_S3_*` — фронтенд самого шлюза, те, кто входит в него; `S3VAULT_S3_*` — пара, которой шлюз сам представляется своему хранилищу (фронтенд-ключи следующего шлюза, если хранилище — шлюз, иначе креды S3). Это разные пары, задать их одинаковыми не мешает ничего, но тогда шлюз держит и ключи от себя, и ключи в хранилище. Наглядная разбивка — в «Быстрый старте», назначение полей по ролям — в [architecture.md](architecture.md#which-config-keys-each-role-reads).

```text
исходные файлы на диске
   │
   ▼
клиент: archive | upload                     клиент: download
   │                                              │
   └──────── S3-протокол ────────────► шлюз ────► хранилище
      (или напрямую в хранилище       (server; сам клиент хранилища)
       когда s3.endpoint — реальный S3)
```

Отсюда два правила, которые иначе приходится выводить самим:

- **Слоёв в объекте столько, сколько s3vault-процессов обернули байты.** Клиент пишет прямо в хранилище — 1 слой. На пути есть шлюз — 2 (внешний шлюзовой, внутренний клиентский). `aws s3 cp` в шлюз даёт 1 слой: клиент, который не s3vault, ничего не добавляет.
- **Чтение снимает ровно один слой.** Поэтому объект читается как plaintext одним процессом только если в нём ровно один слой. Если шлюз есть на пути записи, он обязан быть и на пути чтения: два слоя снимают два разных процесса, по порядку.

### Топология A — клиент напрямую в S3

Самая обычная. Шлюза нет, слоёв один, клиент ходит в S3 напрямую.

```bash
export S3VAULT_S3_ENDPOINT=http://s3.local.example
export S3VAULT_S3_BUCKET=test
export S3VAULT_S3_ACCESS_KEY=... S3VAULT_S3_SECRET_KEY=...
s3vault archive /data/app --older-than 7d
s3vault download backups/logs/app.log /tmp/app.log
```

### Топология B — клиенты без CryptoPro через шлюз

Шлюз с `encryption.mode: command` держит СКЗИ. Клиент без CryptoPro указывает `s3.endpoint` **на S3-фасад шлюза** и использует его frontend-ключи как свои S3-креды. Отдельного канала записи нет: `archive`/`upload` кладут объект по `PutObject`, шлюз добавляет свой слой.

```bash
# на хосте-шлюзе
# ── Хранилище: доступ шлюза к S3 (backend.type=s3 по умолчанию) ──
export S3VAULT_S3_ENDPOINT=http://s3.local.example:9000
export S3VAULT_S3_REGION=us-east-1
export S3VAULT_S3_BUCKET=s3vault           # реальный бакет в хранилище
export S3VAULT_S3_ACCESS_KEY=...
export S3VAULT_S3_SECRET_KEY=...
export S3VAULT_S3_PATH_STYLE=true          # обычно для MinIO
# S3VAULT_S3_PREFIX=backups                # необязательно: общий корень ключей

# ── СКЗИ: command + КриптоПро (cryptcp через обёртки) ──
export S3VAULT_ENCRYPTION_MODE=command
export S3VAULT_ENCRYPTION_COMMAND_PROVIDER=cryptopro      # дефолт cryptopro
export S3VAULT_ENCRYPTION_COMMAND_THUMBPRINT=afa43c43975fbfc700f051fd62016e1571e7e025
export S3VAULT_ENCRYPTION_COMMAND_ENCRYPT=/usr/local/libexec/s3vault/cryptcp-encrypt
export S3VAULT_ENCRYPTION_COMMAND_DECRYPT=/usr/local/libexec/s3vault/cryptcp-decrypt
export S3VAULT_ENCRYPTION_COMMAND_TIMEOUT=30m             # дефолт 30m
export CRYPTOPRO_PIN=...            # только download/server, если контейнер защищён паролем
# CRYPTCP=/opt/cprocsp/bin/ia32/cryptcp                    # 32-bit; дефолт amd64

# ── S3-фасад: ключи, по которым в шлюз ходят клиенты ──
export S3VAULT_SERVER_S3_ACCESS_KEY=vaultak
export S3VAULT_SERVER_S3_SECRET_KEY=vaultsk
export S3VAULT_SERVER_S3_BUCKET=my-bucket  # виртуальный бакет фасада
s3vault server --s3-listen 127.0.0.1:8333

# на хосте-клиенте — s3.* смотрит на шлюз, своих ключей CryptoPro/S3 нет
export S3VAULT_S3_ENDPOINT=http://gw.example:8333
export S3VAULT_S3_ACCESS_KEY=vaultak
export S3VAULT_S3_SECRET_KEY=vaultsk
export S3VAULT_S3_BUCKET=my-bucket
export S3VAULT_S3_PATH_STYLE=true
s3vault archive /var/log/app --older-than 7d
s3vault download logs/app/app.log /tmp/app.log   # читается тем же путём
```

Обязательны `S3VAULT_ENCRYPTION_MODE=command` и обе argv-обёртки `..._ENCRYPT`/`..._DECRYPT` — без них старт падает (`encryption.command encrypt and decrypt argv must be set`). `PROVIDER=cryptopro` и `TIMEOUT=30m` — дефолтные. `THUMBPRINT` здесь обязателен: в argv только путь обёртки, авто-вывод из argv пуст, а обёртка без `CRYPTOPRO_THUMBPRINT`/аргумента завершается ошибкой; списки argv из env — через запятую. `CRYPTOPRO_PIN` — только env и только для защищённого контейнера на `download`/`server`. Сертификат, контейнер и обёртки — раздел «КриптоПро CSP (`cryptcp`)» ниже; YAML-эквивалент — `s3vault.example.yaml:37–43`.

`S3VAULT_S3_*` на шлюзе — это доступ **шлюза к хранилищу** (backend), а `S3VAULT_SERVER_S3_*` — frontend-ключи и виртуальный бакет **S3-фасада**, по которым в шлюз ходят клиенты. Это две независимые пары: backend-креды на клиент не попадают, а бакет хранилища (`S3VAULT_S3_BUCKET=s3vault`) не обязан совпадать с виртуальным бакетом фасада (`S3VAULT_SERVER_S3_BUCKET=my-bucket`). Полная форма — секции `s3:` и `server:` в [s3vault.example.yaml](s3vault.example.yaml); при `backend.type: local` вместо `S3VAULT_S3_*` см. топологию C.

`S3VAULT_SERVER_S3_BUCKET` в примере не декоративный: клиентский `S3VAULT_S3_BUCKET` должен совпасть с виртуальным бакетом фасада, иначе первая же операция вернёт `403 Forbidden`. Без этой строки бакет шлюза берётся из его `s3.bucket`; `S3VAULT_SERVER_S3_BUCKET_AS_PREFIX=true` допускает любое имя на стороне клиента, превращая его в префикс ключа.

**Клиент читает и пишет симметрично.** Оба направления идут через один и тот же `s3.endpoint`, поэтому объект в двух слоях (внешний шлюзовой, внутренний клиентский) снимается двумя процессами по порядку: шлюз снимает свой слой на `GetObject`, клиент — свой на `download`. Былого «только запись» больше нет. Удалены вместе с режимом: `remote.url`, `S3VAULT_SERVER_TOKEN` и лимитер `remote.rate_limit_bps`.

Рабочий пример этого контура — [example/command/gateway.sh](example/command/gateway.sh) (шлюз с `encryption.mode=command`, где внешняя команда — `openssl`, ключ из thumbprint) и [example/command/archive.sh](example/command/archive.sh) (архив каталога через фасад).

### Топология C — шлюз поверх локального каталога

`backend.type: local` — хранилище на той же машине. Шлюз при этом всё равно клиент хранилища, и S3-фасад работает без настоящего бакета (имя виртуального бакета — `server.s3_bucket`, иначе `s3.bucket`, иначе `s3vault`).

```bash
export S3VAULT_BACKEND_TYPE=local
export S3VAULT_BACKEND_LOCAL_DIR=/srv/s3vault/objects
export S3VAULT_SERVER_S3_ACCESS_KEY=vaultak
export S3VAULT_SERVER_S3_SECRET_KEY=vaultsk
s3vault server --s3-listen 127.0.0.1:8333
```

Подробности ролей и таблица «какие ключи читает какая роль» — [architecture.md](architecture.md#roles-and-topology).

## Развёртывание

1. Соберите бинарь на машине, где лежат логи/данные, либо скопируйте `bin/s3vault`.
2. Создайте бакет в AWS S3 или MinIO / другом S3-compatible API.
3. Задайте конфигурацию (файл и/или переменные окружения). **Секреты не кладите в YAML** — используйте env или файлы ключей с правами `0600`.
4. Проверьте список файлов без загрузки: `s3vault archive /data/app --dry-run`.
5. Запустите реальный `archive`, затем при необходимости `download` или `server`.
6. По желанию повесьте `archive` на cron/systemd timer.

Бинарный файл не требует runtime, кроме доступа к диску, сети до S3 и (для `command`) внешней программы шифрования в `PATH`.

### Конфигурация

Приоритет: **флаги CLI > переменные окружения > YAML > значения по умолчанию**.

Файл (необязателен): `--config path.yaml`, иначе `./s3vault.yaml` или `$XDG_CONFIG_HOME/s3vault/s3vault.yaml`.

Пример: [s3vault.example.yaml](s3vault.example.yaml).

Переменные — префикс `S3VAULT_`, точки в ключе заменяются на `_`:

| Переменная | Назначение |
| --- | --- |
| `S3VAULT_BACKEND_TYPE` | Бэкенд хранения: `s3` (по умолчанию) или `local` |
| `S3VAULT_BACKEND_LOCAL_DIR` | Директория объектов при `backend.type=local` |
| `S3VAULT_S3_ENDPOINT` | URL API. Пусто = AWS. Для MinIO: `http://s3.example:9000` |
| `S3VAULT_S3_REGION` | Регион (для MinIO часто `us-east-1`) |
| `S3VAULT_S3_BUCKET` | Бакет |
| `S3VAULT_S3_PREFIX` | Префикс ключей объектов |
| `S3VAULT_S3_ACCESS_KEY` | Access key |
| `S3VAULT_S3_SECRET_KEY` | Secret key |
| `S3VAULT_S3_SESSION_TOKEN` | Session token, если нужен |
| `S3VAULT_S3_PATH_STYLE` | `true` для большинства MinIO |
| `S3VAULT_ENCRYPTION_MODE` | `none`, `native`, `command` |
| `S3VAULT_LOG_LEVEL` | `debug`, `info`, `warn`, `error` |
| `S3VAULT_CACHE_ENABLED` | `true` — persistent plaintext disk cache for HTTP/S3 (default `false`) |
| `S3VAULT_SERVER_S3_ACCESS_KEY` | Frontend SigV4 access key (обязателен вместе с secret) |
| `S3VAULT_SERVER_S3_SECRET_KEY` | Frontend SigV4 secret |
| `S3VAULT_SERVER_S3_LISTEN` | Отдельный bind для S3; пусто = multiplex на `server.listen` |
| `S3VAULT_SERVER_S3_BUCKET` | Virtual bucket name (default = `s3.bucket`) |
| `S3VAULT_SERVER_S3_BUCKET_AS_PREFIX` | `true` — имя bucket в URL → префикс ключа в backend (default `false`) |
| `S3VAULT_SERVER_S3_REGION` | Region для SigV4 (default `us-east-1`) |

Файл `.env` использует те же имена `S3VAULT_*`. CLI его сам не читает — сделайте `set -a && source .env && set +a` или экспортируйте переменные иначе. Integration-тесты подхватывают `.env` автоматически.

### Бэкенд хранения: S3 или локальная директория

`backend.type` выбирает, куда пишет `archive` / `upload` и откуда читают `download` и `server`:

```yaml
backend:
  type: local
  local:
    dir: /srv/s3vault/objects
```

Форму объекта задаёт **только** `encryption.mode`, на любом бэкенде: `none` — голый
payload без контейнера, `native`/`command` — `S3VCTR01` + payload. Отдельного ключа
`backend.local.layout` больше нет, и оставшийся ключ отвергается на старте.

То же самое только через окружение — YAML при этом не нужен вовсе:

```bash
export S3VAULT_BACKEND_TYPE=local
export S3VAULT_BACKEND_LOCAL_DIR=/srv/s3vault/objects
export S3VAULT_S3_PREFIX=backups          # необязательно: общий префикс ключей

s3vault archive /data/app --older-than 7d
s3vault download backups/app.log /tmp/app.log
```

Как и для остальных настроек, приоритет прежний: флаги > `S3VAULT_*` > YAML > умолчания, так что `S3VAULT_BACKEND_TYPE=local` переопределяет `backend.type: s3` из файла.

При `type: local` секция `s3:` не нужна (кроме `s3.prefix`, если хотите общий префикс ключей), а ключи объектов становятся путями внутри `dir`: `backups/logs/app.log` → `/srv/s3vault/objects/backups/logs/app.log`. Бэкенд хранит байты ровно как их отдали, поэтому при одном и том же `encryption.mode` формат объекта совпадает с S3, и шифрование, dedup по SHA-256, `download` и S3 SigV4-фасад работают одинаково на обоих. Директория создаётся с правами `0700`, файлы объектов — `0600`, запись атомарна (temp-файл в `.s3vault-tmp/` + `rename`).

`encryption.mode: none` пишет **голый payload без заголовка `S3VCTR01`** — в каталоге (и в бакете) получаются обычные файлы. Это удобно, если содержимое должны читать/писать другие инструменты или человек, и верно на любом бэкенде, включая S3.

Что из этого следует: без заголовка хранить `enc` некуда, но и не нужно — режим `none` по определению ничего не шифрует, поэтому payload всегда plaintext. Идентичность объекта едет в S3 user-metadata (`s3vault-sha256`, `s3vault-size`), а на локальном бэкенде выводится хешированием файла, поэтому dedup по SHA, `--delete-if-exists` и `x-amz-checksum-sha256` продолжают работать. `ETag` локального бэкенда остаётся синтетическим (размер + mtime) и используется только как fallback.

Единственное место, где объект без контейнера читается «на глаз», — `decryptLegacy`: без заголовка нет `enc`, и остаётся magic/type-детекция. Она проверяет обе магии шифротекста (`S3VLT01` и конверт OpenSSL `Salted__`) и при совпадении **отказывается**, а не копирует мусор. Ложное срабатывание возможно только на 8-байтовом префиксе: plaintext-файл, начинающийся с `Salted__`, будет отвергнут с внятной ошибкой.

Особенности локального бэкенда: `ListObjectsV2` обходит всё дерево (стоимость линейна по числу объектов); ключ не может одновременно быть файлом и каталогом (в S3 допустимы и `a`, и `a/b`); ETag синтетический (размер + mtime) и служит только fallback, а идентичность содержимого — plaintext SHA-256 из заголовка `S3VCTR01`, а для объекта без контейнера — SHA-256 самого файла, вычисляемый один раз на объект и мемоизируемый в процессе.

Смена бэкенда меняет namespace дискового кэша, поэтому записи S3 и локального хранилища в кэше не пересекаются.

### MinIO / S3-compatible

```yaml
s3:
  endpoint: http://s3.local.example
  region: us-east-1
  bucket: test
  prefix: backups
  path_style: true
```

Для `http://` endpoint задайте его явно; `path_style: true` обычно обязателен. Регион нужен SDK даже если MinIO его не использует.

TLS отдельным ключом не настраивается: его определяет схема `endpoint`. `https://` проверяет сертификат по системному хранилищу (проверка включена по умолчанию), `http://` отключает TLS. Это сознательно — иначе булев флаг и URL смогли бы разойтись, и оператор думал бы, что управляет TLS, не управляя им.

Либо:

```bash
export S3VAULT_S3_ENDPOINT=http://s3.local.example
export S3VAULT_S3_REGION=us-east-1
export S3VAULT_S3_BUCKET=test
export S3VAULT_S3_PATH_STYLE=true
export S3VAULT_S3_ACCESS_KEY=...
export S3VAULT_S3_SECRET_KEY=...
```

Можно опереться на стандартную цепочку AWS (`AWS_ACCESS_KEY_ID`, `~/.aws/credentials`), если не заданы `S3VAULT_S3_ACCESS_KEY` / `SECRET_KEY`.

### Команды

```bash
# Какие файлы ушли бы в хранилище (mtime старше 7 дней)
s3vault archive /data/app --older-than 7d --dry-run --prefix backups

# Загрузка
s3vault archive /data/app --older-than 7d --bucket test --prefix backups --workers 4

# Два префикса в одном проекте — два запуска (или два unit/cron):
s3vault archive /data/sopd --older-than 7d --prefix fs.auto-sopd
s3vault archive /data/avatars --older-than 7d --prefix fs.auto-user-avatars
# → fs.auto-sopd/... и fs.auto-user-avatars/... в бакете

# Загрузка одного файла (без фильтра по mtime)
s3vault upload /var/log/app.log --prefix backups
s3vault upload /data/app/logs/app.log --root /data/app --prefix backups --key logs/app.log

# Скачать и расшифровать в файл (или "-" — stdout)
s3vault download backups/logs/app.log /tmp/app.log
```

Ключ объекта: `prefix` + путь относительно корня скана (`archive <dir>` / `upload --root`). Префикс: `--prefix`, `S3VAULT_S3_PREFIX` или `s3.prefix` в YAML (флаг сильнее). Когда клиент ходит через шлюз, его `--prefix` входит в ключ `PutObject`, а `s3.prefix` шлюза — общий корень (часто пустой, если префиксы задаёт только клиент).

`--older-than`: Go-duration (`24h`, `90m`) плюс `7d`, `30d`, `1w`.

Симлинки по умолчанию пропускаются. Локальный файл после upload остаётся на диске.

Логи — структурированные в stderr, итоговая строка archive — в stdout (`--output json` для машинного вида).

Первая строка лога любой команды, работающей с хранилищем (`archive`, `upload`, `download`, `server`), показывает выбранный бэкенд и куда именно пишутся объекты:

```text
level=INFO msg="object store ready" op=backend backend=local dir=/srv/s3vault/objects prefix=backups
level=INFO msg="object store ready" op=backend backend=s3 bucket=my-bucket endpoint="" prefix=backups
```

## Шифрование

Режим задаётся `encryption.mode`. RSA **не** шифрует тело файла: только оборачивает случайный AES-ключ (envelope). Большие файлы идут потоком, чанками AES-256-GCM.

Формат объекта зависит от `encryption.mode`. `native`/`command`: сначала фиксированный контейнер `S3VCTR01` (identity, enc, wrap, provider, thumbprint; +128 байт), затем payload; native-шифрование внутри — magic `S3VLT01`. `none`: только payload, без контейнера, а SHA-256 plaintext кладётся в user-metadata объекта. В обоих случаях `download` снимает свой слой сам.

Identity и CryptoPro thumbprint берутся из `S3VCTR01` (на archive — Range GET первых 128 байт). Исключение — `mode=none`: контейнера нет, и identity пишется в S3 user-metadata (`s3vault-sha256`, `s3vault-size`), который читается на `HEAD`. Для контейнерных объектов user-metadata по-прежнему не пишется. Бэкенд должен поддерживать HTTP Range.

Объект без контейнера читается по magic/type-детекции, и громкость сообщения зависит от режима читателя: при `mode=none` это его собственная форма объекта (debug), при `native`/`command` — неожиданная (warn).

### `none` — без шифрования

Значение по умолчанию. В S3 уходит plaintext.

```yaml
encryption:
  mode: none
```

### `native` + `keyfile` — симметричный KEK

Файл шифруется AES-256-GCM. DEK оборачивается тем же AES-GCM ключом из файла: ровно 32 байта или SHA-256 от содержимого файла.

```bash
umask 077
dd if=/dev/urandom of=/etc/s3vault/kek.bin bs=32 count=1
```

```yaml
encryption:
  mode: native
  native:
    wrap: keyfile
    key_file: /etc/s3vault/kek.bin
    chunk_size: 65536
```

Проще в эксплуатации (один секрет). Кто читает `kek.bin`, читает все объекты. Права на файл — `0600`, каталог — `0700`.

### `native` + `rsa-oaep` — RSA только для ключа

Файл снова AES-256-GCM. DEK шифруется RSA-OAEP (SHA-256). Для upload достаточно публичного ключа; для download — закрытого.

```bash
umask 077
openssl genrsa -out /etc/s3vault/private.pem 2048
openssl rsa -in /etc/s3vault/private.pem -pubout -out /etc/s3vault/public.pem
chmod 600 /etc/s3vault/private.pem
chmod 644 /etc/s3vault/public.pem   # public можно шире
```

```yaml
encryption:
  mode: native
  native:
    wrap: rsa-oaep
    public_key_path: /etc/s3vault/public.pem
    private_key_path: /etc/s3vault/private.pem
    chunk_size: 65536
```

На хосте, который только архивирует, можно оставить `public_key_path`. Хост `download` / `server` держит `private.pem`.

Не используйте RSA напрямую на содержимое логов — в s3vault этого нет.

### `command` — внешняя программа

Поток: stdin → команда → stdout. Без shell, argv списком. Код возврата ≠ 0 — ошибка. stderr обрезается. Секреты передавайте через окружение процесса, не через аргументы.

```yaml
encryption:
  mode: command
  command:
    encrypt: ["/usr/bin/age", "-r", "age1...recipient..."]
    decrypt: ["/usr/bin/age", "-d", "-i", "/etc/s3vault/age-identity"]
    timeout: 30m
```

Подходит `age`, `gpg` (осторожно с pinentry), КриптоПро `cryptcp` (через обёртку, см. ниже), любой фильтр stdin→stdout. Формат объекта тогда свой у команды; `download` запускает decrypt-команду только для объектов с `enc=command` в заголовке (и для legacy-объектов без контейнера); если объект помечен `enc=0`, читатель `command` отказывается.

Пример identity `age`:

```bash
age-keygen -o /etc/s3vault/age-identity
chmod 600 /etc/s3vault/age-identity
```

В `encrypt` укажите публичный recipient из комментария ключа.

#### КриптоПро CSP (`cryptcp`)

Шифрование ГОСТ на Linux — утилита `cryptcp` из КриптоПро CSP. Типичный путь: `/opt/cprocsp/bin/amd64/cryptcp` (на 32-bit — `ia32`). Получатель задаётся **SHA-1 thumbprint** сертификата в хранилище CSP, не путём к файлу `.cer`.

##### Сертификат и контейнер ключа

Самоподписанный сертификат обмена (GOST R 34.10-2012) и контейнер:

```bash
csptest -minica -root \
  -dn "CN=S3 External File Crypt 2026, O=OOO LAB, C=RU" \
  -provtype 80 \
  -provider "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider" \
  -container "s3_external_file_crypt_2026" \
  -fcert "mycert.cer" \
  -keytype exchange \
  -until 1825
```

Удаление пароля с контейнера:
```bash
csptest -passwd -change '' -cont '\\.\HDIMAGE\s3_external_file_crypt_2026' -passwd AitahV7i
```

Установка сертификата в хранилище текущего пользователя с привязкой к контейнеру:

```bash
certmgr -inst -store My \
  -file mycert.cer \
  -cont '\\.\HDIMAGE\s3_external_file_crypt_2026'
```

Если `csptest` запускали от root, `-file` может указывать в каталог контейнера, например `/var/opt/cprocsp/keys/root/<имя>/mycert.cer`. Контейнер и сертификат должны быть видны **тому пользователю**, от которого запускается s3vault.

Thumbprint после установки:

```bash
certmgr -list -store My
```

Ищите SHA1 Thumbprint / отпечаток (40 hex-символов без пробелов и двоеточий), например `afa43c43975fbfc700f051fd62016e1571e7e025`.

##### Вызов cryptcp

Сама утилита работает **с путями к файлам**, не как фильтр stdin/stdout:

```bash
cryptcp -encr -der -thumbprint "afa43c43975fbfc700f051fd62016e1571e7e025" test.txt test.txt.enc
cryptcp -decr -nochain -thumbprint "afa43c43975fbfc700f051fd62016e1571e7e025" -pin AitahV7i test.txt.enc test-decoded.txt
```

- `-thumbprint` — SHA-1 сертификата получателя в хранилище.
- `-der` — бинарный CMS в объект (без `-der` cryptcp пишет base64, примерно +33% к размеру ciphertext).
- `-nochain` — не проверять цепочку УЦ (нужно для самоподписанного `csptest -minica`).
- `-pin` — пароль контейнера закрытого ключа, если контейнер защищён. Для `-encr` не нужен.

Для маленьких файлов (~200 B) сам CMS/PKCS#7 всё равно даёт сотни байт оверхеда (сертификат получателя, обёрнутый DEK, ASN.1). Base64 сверху убирается флагом `-der` в [scripts/cryptcp-encrypt](scripts/cryptcp-encrypt); `-decr` принимает и DER, и старые base64-объекты. На больших логах относительный прирост падает.

s3vault в режиме `command` подаёт plaintext на **stdin** и ждёт ciphertext на **stdout**, без shell. Поэтому `cryptcp` нельзя указать напрямую в `encryption.command.encrypt`: диагностический вывод CSP испортит объект в S3. Нужна обёртка, которая пишет временные файлы (`0600`), вызывает `cryptcp`, а в stdout отдаёт только результат. В репозитории: [scripts/cryptcp-encrypt](scripts/cryptcp-encrypt) и [scripts/cryptcp-decrypt](scripts/cryptcp-decrypt).

```bash
install -d -m 0700 /usr/local/libexec/s3vault
install -m 0700 scripts/cryptcp-encrypt scripts/cryptcp-decrypt /usr/local/libexec/s3vault/
# ia32: export CRYPTCP=/opt/cprocsp/bin/ia32/cryptcp
```

Thumbprint — в `encryption.command.thumbprint` и/или вторым аргументом обёртки encrypt (это идентификатор сертификата, не секрет). При upload s3vault пишет его вместе с `provider` (по умолчанию `cryptopro`) в заголовок `S3VCTR01`. При download/server thumbprint для decrypt берётся в порядке: контейнер → legacy metadata → конфиг/argv, и передаётся в обёртку через `CRYPTOPRO_THUMBPRINT`. PIN контейнера — **только** `CRYPTOPRO_PIN`, не YAML и не argv:

```yaml
encryption:
  mode: command
  command:
    provider: cryptopro
    thumbprint: "afa43c43975fbfc700f051fd62016e1571e7e025"
    encrypt: ["/usr/local/libexec/s3vault/cryptcp-encrypt"]
    decrypt: ["/usr/local/libexec/s3vault/cryptcp-decrypt"]
    timeout: 30m
```

```bash
# только на download / server, если контейнер с паролем
export CRYPTOPRO_PIN="..."
```

На машине **archive** достаточно сертификата получателя в хранилище (thumbprint). На машине **download** / **server** должен быть контейнер закрытого ключа того же получателя (и старых thumbprint’ов из контейнера/metadata, пока объекты не перешифрованы); процесс s3vault запускают от пользователя, у которого CSP эти контейнеры видит. Если контейнер закрыт паролем, без `CRYPTOPRO_PIN` расшифровка не пройдёт.

Если на источнике логов **нет** CryptoPro, а на шлюзе (`s3vault server`) уже настроены `encryption.mode=command` и S3-фасад: укажите на клиенте `s3.endpoint` **на шлюз** и его frontend-ключи `server.s3_access_key`/`server.s3_secret_key` (см. «Режимы работы», топология B). `archive`/`upload` положат объект на шлюз по S3, шифрование выполнится там; `download` читает тем же путём. Ключи `S3VAULT_REMOTE_URL`/`S3VAULT_SERVER_TOKEN` удалены.

Legacy-объекты без `S3VCTR01` / без metadata расшифровываются thumbprint’ом из конфига / argv.

Подпись (`-sign`) при архивации не нужна — только `-encr`/`-decr`.

Срок закрытого ключа ГОСТ в СКЗИ ограничен (часто около 1–3 лет). Для архива на годы не выпускайте «один ключ на 50 лет» штатными средствами CSP и не стройте процесс на отключении проверки срока ключа. Рабочая схема: шифровать действующим сертификатом и **перешифровывать** свежим ключом до истечения старого (или хранить аварийный экспорт ключа по регламенту ИБ, это уже не задача s3vault).

### Как выбрать

| Режим | Когда брать |
| --- | --- |
| `none` | Доверенный бакет / SSE на стороне S3 достаточно |
| `native` + `keyfile` | Client-side, один секрет, проще ops |
| `native` + `rsa-oaep` | Upload без приватного ключа на источнике логов |
| `command` | Уже есть `age` / `gpg` / КриптоПро `cryptcp` |

Смена ключа без изменения файла **не** перезаливает объект (skip по plaintext hash). Перешифровка — отдельная операция, её пока нет.

#### Плюсы и минусы

**`none`**

- Плюсы: нулевая сложность и CPU; объекты читаются любым S3-клиентом; нет ключей для ротации.
- Минусы: содержимое видно всем с доступом к бакету (и бэкапам бакета); полагаетесь только на ACL/IAM и опционально SSE провайдера; не подходит, если бакет или оператор хранилища не доверен.

**`native` + `keyfile`**

- Плюсы: client-side AES без внешних утилит; один файл-секрет; быстрый потоковый путь; формат `S3VLT01` свой, понятный s3vault на download/server.
- Минусы: один KEK открывает весь архив — компрометация файла = компрометация истории; KEK нужен и на archive, и на download/server; ротация KEK без перешифровки старых объектов не даёт эффекта (skip по plaintext hash).

**`native` + `rsa-oaep`**

- Плюсы: на машине archive достаточно **публичного** ключа (утечка источника логов не отдаёт расшифровку); приватный ключ только на download/server; тот же быстрый native AES-поток и `S3VLT01`.
- Минусы: нужно хранить и бэкапить `private.pem`; смена пары ключей не перезаливает старые объекты автоматически; RSA оборачивает только DEK (это плюс по дизайну, но ИБ-аудит иногда ожидает «ГОСТ/сертификат» — тогда это не тот режим).

**`command` (age / gpg / произвольный фильтр)**

- Плюсы: можно опереться на уже принятый в компании инструмент; recipient-модель (`age`, gpg) без своего формата ключей s3vault; гибкость argv/env.
- Минусы: зависимость от внешней программы в `PATH`; stderr/pinentry легко сломать пайплайн; формат объекта «чужой» — download **всегда** гоняет decrypt-команду (нет magic auto-detect как у native); сложнее отладка и таймауты (`encryption.command.timeout`).

**`command` + КриптоПро (`cryptcp`)**

- Плюсы: шифрование ГОСТ / сертификаты CSP; соответствует требованиям, где нужен СКЗИ; на archive достаточно сертификата получателя; thumbprint в `S3VCTR01`/metadata позволяет расшифровывать старые объекты после смены сертификата; клиент без CryptoPro может держать `mode: none` и переложить шифрование на шлюз — тогда объект уходит в фасад открытым, а слой кладёт шлюз.
- Минусы: лицензия и установка CSP; обёртки вместо прямого `cryptcp` (stdin/stdout); PIN только через `CRYPTOPRO_PIN`; срок закрытого ключа ГОСТ обычно 1–3 года — нужна плановая перешифровка; тяжелее и медленнее native AES; на download/server нужен контейнер того же (и старых) получателя.


## Тесты против живого S3

Integration-тесты читают корневой `.env` (те же `S3VAULT_*`, что и приложение; переменные процесса имеют приоритет). Если `S3VAULT_S3_ENDPOINT`, `S3VAULT_S3_BUCKET`, `S3VAULT_S3_ACCESS_KEY` и `S3VAULT_S3_SECRET_KEY` не заданы, тесты пропускаются (`t.Skip`), а не падают.

```bash
# .env — не коммитить; см. .env.example
S3VAULT_S3_ENDPOINT=http://s3.example
S3VAULT_S3_BUCKET=test
S3VAULT_S3_REGION=us-east-1
S3VAULT_S3_PATH_STYLE=true
S3VAULT_S3_ACCESS_KEY=...
S3VAULT_S3_SECRET_KEY=...

go test -tags=integration -count=1 -v ./internal/integration/
```

Объекты пишутся под `s3vault-it/` и удаляются в cleanup.

## E2E-стенд

`make e2e` поднимает MinIO из `compose.e2e.yaml` (бакет создаётся через `minio-init`, сам код `CreateBucket` не вызывает) и прогоняет все фазы: `go test -race ./...`, integration-тесты, CLI (archive/upload/download, перезапись по ключу, delete-политики, симлинки, multipart), все режимы шифрования, HTTP-сервер (health/ready, Range, метрики, кэш), SigV4-фасад, локальный бэкенд и отказы.

```bash
make e2e            # всё
make e2e-up         # только MinIO
make e2e-down       # снести стенд
make e2e-clean      # снести стенд и рабочий каталог
./scripts/e2e.sh server   # одна фаза: go|cli|encrypt|server|facade|local|resilience
```

Стенды детектора шифрования живут отдельно от `e2e.sh` (они проверяют не
сценарии CLI, а инварианты чтения), но тоже прогоняются в CI шагом `make verify`.
Локально нужен поднятый MinIO на `127.0.0.1:9000` и бакет `s3vault` — то есть
`make e2e-up`:

```bash
make verify                  # все три
make verify-detect           # детектор шифрования, T0–T7
make verify-layers           # матрица «сервер × клиент» через фасад
make verify-drift            # дрейф encryption.mode на сервере
```

Подробности — в [docs/decrypt-detection.md](docs/decrypt-detection.md).

Нужен `socat` (для имитации отказа S3) и доступ к Docker. Рабочий каталог — per-uid, `/tmp/s3vault-e2e-$(id -u)`, чтобы два пользователя на одной машине не ломали друг другу сборку бинаря и кэш.

Если MinIO уже поднят (CI-сервис или чужой стенд), compose не трогается:

```bash
S3VAULT_E2E_NO_COMPOSE=1 ./scripts/e2e.sh all
```

Переопределяются через окружение: `S3VAULT_E2E_MINIO_API`, `S3VAULT_E2E_HTTP_PORT`, `S3VAULT_E2E_S3_PORT`, `S3VAULT_E2E_METRICS_PORT`, `S3VAULT_E2E_WORK`, `S3VAULT_E2E_RUN_ID`.

Режим `encryption.mode=command` проверяется подменой `cryptcp` — скриптом `scripts/e2e/fakecryptcp`, который повторяет контракт настоящего `cryptcp` (argv, `CRYPTOPRO_THUMBPRINT` из env, ключевой материал из SHA-1 thumbprint), но **не является криптографией и не ГОСТ**. Он существует, чтобы проверить конвейер s3vault — argv без shell, roundtrip, ротацию ключа, — а не реализацию CryptoPro.

Полезно знать при чтении тестов:

- Ключ объекта = `s3.prefix` + путь **относительно сканируемого корня**. `archive /data/logs` над единственным `app.log` кладёт объект в `<prefix>/app.log`, а не `<prefix>/logs/app.log`.
- Формат native-шифрования — `S3VCTR01 || S3VLT01 || chunks`: магия контейнера в начале объекта, магия шифротекста — сразу за 128-байтовым заголовком.
- Идентичность читается из CRC-заголовка `S3VCTR01`, тело при `Head` не проверяется. Повреждённый AEAD-тег поэтому не мешает `archive` пройти как «идентичный» объект — порчу ловит только `download`. Это осознанный контракт (смена ключей не перезаливает неизменный plaintext), а не пропущенная проверка.
- Клиент, ходящий через шлюз, включает свой `s3.prefix` в ключ объекта (`PutObject`), а шлюз добавляет свой `s3.prefix` общим корнем. Одинаковые префиксы у клиента и шлюза дают ключ с удвоением.
- `--fail-fast` видно только при `--workers 1`. При 4 воркерах все файлы уже в полёте и падают заподряд, поэтому счётчик отказов одинаковый. Стенд проверяет обе стороны, чтобы отличие флагов не осталось на словах.
- Приоритет флагов над окружением проверяется на `--prefix`: объект обязан лечь в `flagprefix/...`, а не в `$S3VAULT_S3_PREFIX/flagprefix/...`.

## HTTP-сервер

Здесь `s3vault server` — это **шлюз** (см. «Режимы работы»): своего хранилища у него нет, он стоит перед хранилищем и сам ходит в него как клиент. Слушает `127.0.0.1:8080` по умолчанию. Единственный фронтенд данных — **S3-совместимый API** (SigV4, path-style): Get/Put/Delete/List через `Fetch`/`Archive` (и кэш, если включён). Список — только ListObjectsV2; запрос v1 (`list-type` ≠ 2 или `marker` без `list-type`) отклоняется с `501 NotImplemented`. Обычный HTTP-слушатель отдаёт только `/health` и `/ready`.

S3-фасад **обязателен**: без пары `server.s3_access_key` / `server.s3_secret_key` процесс не стартует. Bearer-токен `server.token` и маршруты `HTTP /files` удалены — шлюз говорит с клиентами только по S3.

```bash
export S3VAULT_SERVER_S3_ACCESS_KEY=vaultak
export S3VAULT_SERVER_S3_SECRET_KEY=vaultsk
# опционально отдельный порт: --s3-listen 127.0.0.1:8333
# иначе multiplex на --listen (/health /ready остаются HTTP-путями)
s3vault server --listen 127.0.0.1:8080

aws --endpoint-url http://127.0.0.1:8080 s3api list-objects-v2 --bucket my-bucket
aws --endpoint-url http://127.0.0.1:8080 s3 cp ./file s3://my-bucket/logs/file --region us-east-1
# клиенту нужен path-style (UsePathStyle / s3ForcePathStyle)
```

### Доступ извне

Любой bind — и loopback, и внешний — требует ключей `server.s3_access_key` / `server.s3_secret_key` (env `S3VAULT_SERVER_S3_ACCESS_KEY` / `S3VAULT_SERVER_S3_SECRET_KEY`): это единственный фронтенд и единственный способ аутентификации. Без них старт падает с `S3 API credentials required`. Если внешний доступ не нужен, всё равно задайте пару ключей и ходите через reverse proxy / SSH-туннель. Если задан `server.s3_listen` (или `--s3-listen`) без ключей — старт тоже падает.

### S3 API (aws-cli / SDK)

Ключи `S3VAULT_SERVER_S3_*` — **frontend** (SigV4 к vault), не путать с `S3VAULT_S3_*` к backend storage. Virtual bucket: `server.s3_bucket` (по умолчанию = `s3.bucket`, а при локальном бэкенде без него — `s3vault`). При `server.s3_bucket_as_prefix` / `S3VAULT_SERVER_S3_BUCKET_AS_PREFIX=true` любое имя bucket в path-style URL допускается и становится префиксом ключа в backend (`s3://reports/a.log` → `{s3.prefix}/reports/a.log` в `s3.bucket`). Head/Get/Put отдают `x-amz-checksum-sha256` (base64 plaintext SHA-256). Multipart upload в v1 нет.

На хосте **без** CryptoPro / S3-ключей клиент указывает `s3.endpoint` **на фасад шлюза** и его frontend-ключи (см. «Режимы работы», топология B) — `download` читает тем же путём, отдельного канала записи нет.

- `GET /health` — процесс жив.
- `GET /ready` — дешёвый HEAD в бэкенде хранения.
- Prometheus: отдельный `server.metrics_listen` (по умолчанию `127.0.0.1:9090`), путь `/metrics`. Без меток с полным path. На `archive`/`upload`/`download` тот же endpoint можно поднять на время команды через `--metrics-listen`.
- Кэш: по умолчанию выкл. (`cache.enabled` / `S3VAULT_CACHE_ENABLED`). Вкл.: каталог `0700`, файлы `0600`, id = SHA-256(namespace бэкенда, key, enc fingerprint). `s3vault cache stats` / `cache clear`.
- Удалённые ключи (`remote.url`, `remote.rate_limit_bps`, `server.token`) отвергаются на старте — Viper молча игнорирует неизвестные ключи, поэтому устаревший ключ без этого guard’а тихо менял бы поведение.

SIGTERM/SIGINT — graceful `Shutdown` (HTTP + optional S3 listen + metrics).

## Дальше

CI настроен и живёт в `.github/workflows/`, всё на push/PR в `main`, кроме `release.yml` — он на тегах `v*`:

- `go.yml` — build, vet, `go test -race -shuffle=on -count=1`, gofmt, проверка `go.mod`/`go.sum` на tidiness; матрица `1.26` + `stable`;
- `lint.yml` — golangci-lint; `security.yml` — govulncheck (гейт) и gosec (`continue-on-error`);
- `integration.yml` и `e2e.yml` — свои MinIO-сервисы, бакет создаётся через awscli, сам код `CreateBucket` не зовёт;
- `release.yml` + `.goreleaser.yml` — сборка и публикация по тегу.

Две оговорки про обходные пути — это калибровка, а не недосмотр: `lint.yml` гоняется с `only-new-issues: true` (в дереве сотни давних находок, в основном `wsl_v5`, массово их править запрещено — новые всё равно роняют сборку), а `gosec` помечен `continue-on-error` по той же причине.

Чего правда нет: Docker-образ **ни разу не собран** — у исполнителя не было доступа к docker daemon, так что проверялось только то, что проверяется без него. Первую `docker build` прогнать руками. Локально гоняются `make test`, `make e2e` и `make verify` — см. «Тесты против живого S3» и «E2E-стенд».
