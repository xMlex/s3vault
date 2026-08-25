# s3vault

Утилита на Go: находит локальные файлы старше заданного периода, загружает их в S3-совместимое хранилище, при необходимости шифрует на клиенте и скачивает уже в открытом виде.

Повторная загрузка того же содержимого пропускается (SHA-256 plaintext в заголовке объекта `S3VCTR01` и, по возможности, в user-metadata; без опоры на ETag). После успешного upload локальный файл **не удаляется**, пока не указан `--delete-after-upload`. Если объект уже есть с тем же содержимым (skip) — `--delete-if-exists`.

Архитектура: [architecture.md](architecture.md).

## Что уже есть и чего нет

Работает: `archive` (включая `--dry-run`), `upload`, `download`, `server` (расшифрованная раздача из plaintext cache), `cache stats|clear`, шифрование `none` / `native` / `command`, Prometheus-метрики (HTTP, кэш, upload/download).

Docker-образа и systemd-unit в репозитории нет — ниже запуск бинарём.

## Сборка

Нужен Go 1.24+ (в `go.mod` зафиксирована версия toolchain).

```bash
git clone <repo>
cd s3vault
go build -ldflags "-X main.version=$(git describe --tags --always --dirty)" -o bin/s3vault ./cmd/s3vault
# или
make build
```

Проверки:

```bash
go test ./...
go test -tags=integration -count=1 ./internal/integration/   # нужен доступ к S3, см. ниже
```

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
| `S3VAULT_S3_ENDPOINT` | URL API. Пусто = AWS. Для MinIO: `http://s3.example:9000` |
| `S3VAULT_S3_REGION` | Регион (для MinIO часто `us-east-1`) |
| `S3VAULT_S3_BUCKET` | Бакет |
| `S3VAULT_S3_PREFIX` | Префикс ключей объектов |
| `S3VAULT_S3_ACCESS_KEY` | Access key |
| `S3VAULT_S3_SECRET_KEY` | Secret key |
| `S3VAULT_S3_SESSION_TOKEN` | Session token, если нужен |
| `S3VAULT_S3_PATH_STYLE` | `true` для большинства MinIO |
| `S3VAULT_S3_TLS` | Проверка TLS (по умолчанию включена) |
| `S3VAULT_ENCRYPTION_MODE` | `none`, `native`, `command` |
| `S3VAULT_LOG_LEVEL` | `debug`, `info`, `warn`, `error` |

Файл `.env` использует те же имена `S3VAULT_*`. CLI его сам не читает — сделайте `set -a && source .env && set +a` или экспортируйте переменные иначе. Integration-тесты подхватывают `.env` автоматически.

### MinIO / S3-compatible

```yaml
s3:
  endpoint: http://s3.local.example
  region: us-east-1
  bucket: test
  prefix: backups
  path_style: true
  tls: true
```

Для `http://` endpoint задайте его явно; `path_style: true` обычно обязателен. Регион нужен SDK даже если MinIO его не использует.

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
# Какие файлы ушли бы в S3 (mtime старше 7 дней)
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

Ключ объекта: `prefix` + путь относительно корня скана (`archive <dir>` / `upload --root`). Префикс: `--prefix`, `S3VAULT_S3_PREFIX` или `s3.prefix` в YAML (флаг сильнее). В remote-режиме клиентский `--prefix` уходит в путь `PUT /files/...`; на сервере `s3.prefix` — общий корень (часто пустой, если префиксы задаёт только клиент).

`--older-than`: Go-duration (`24h`, `90m`) плюс `7d`, `30d`, `1w`.

Симлинки по умолчанию пропускаются. Локальный файл после upload остаётся на диске.

Логи — JSON в stderr, итоговая строка archive — в stdout (`--output json` для машинного вида).

## Шифрование

Режим задаётся `encryption.mode`. RSA **не** шифрует тело файла: только оборачивает случайный AES-ключ (envelope). Большие файлы идут потоком, чанками AES-256-GCM.

Формат объекта: сначала фиксированный контейнер `S3VCTR01` (identity, enc, wrap, provider, thumbprint; +128 байт), затем payload. Native-шифрование внутри — magic `S3VLT01`. При `download` программа снимает контейнер и расшифровывает payload сама.

Identity и CryptoPro thumbprint берутся из `S3VCTR01` (на archive — Range GET первых 128 байт). S3 user-metadata на новых Put **не** пишется. Бэкенд должен поддерживать HTTP Range.

Один и тот же режим и те же ключи нужны на archive и на download.

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

Подходит `age`, `gpg` (осторожно с pinentry), КриптоПро `cryptcp` (через обёртку, см. ниже), любой фильтр stdin→stdout. Формат объекта тогда свой у команды; download в режиме `command` всегда гоняет decrypt-команду.

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

Если на источнике логов **нет** CryptoPro, а на `s3vault server` уже настроены `encryption.mode=command` и S3: задайте `S3VAULT_REMOTE_URL` + `S3VAULT_SERVER_TOKEN` на клиенте — `archive`/`upload` отправят plaintext на сервер (`PUT /files/...`), шифрование и Put выполнятся там.

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

- Плюсы: шифрование ГОСТ / сертификаты CSP; соответствует требованиям, где нужен СКЗИ; на archive достаточно сертификата получателя; thumbprint в `S3VCTR01`/metadata позволяет расшифровывать старые объекты после смены сертификата; remote-клиент без CryptoPro может слать plaintext на `s3vault server`.
- Минусы: лицензия и установка CSP; обёртки вместо прямого `cryptcp` (stdin/stdout); PIN только через `CRYPTOPRO_PIN`; срок закрытого ключа ГОСТ обычно 1–3 года — нужна плановая перешифровка; тяжелее и медленнее native AES; на download/server нужен контейнер того же (и старых) получателя.


## Тесты против живого S3

Integration-тесты читают корневой `.env` (те же `S3VAULT_*`, что и приложение):

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

## HTTP-сервер

`s3vault server` слушает `127.0.0.1:8080` по умолчанию и отдаёт **plaintext** после полной расшифровки в локальный кэш (`http.ServeContent`, включая Range). Тот же процесс принимает **PUT** plaintext для архивации (шифрование CryptoPro/S3 — на сервере).

```bash
export S3VAULT_SERVER_TOKEN=...   # обязателен, если listen не loopback
s3vault server --listen 127.0.0.1:8080
curl -H "Authorization: Bearer $S3VAULT_SERVER_TOKEN" http://127.0.0.1:8080/files/logs/app.log
# ingest (клиент без CryptoPro):
curl -X PUT -H "Authorization: Bearer $S3VAULT_SERVER_TOKEN" \
  --data-binary @./app.log http://127.0.0.1:8080/files/logs/app.log
```

На хосте **без** CryptoPro / S3-ключей:

```bash
export S3VAULT_REMOTE_URL=https://s3vault.example:8080
export S3VAULT_SERVER_TOKEN=...          # тот же Bearer, что на сервере
export S3VAULT_REMOTE_RATE_LIMIT_BPS=10485760  # опционально, суммарный лимит B/s
s3vault archive /var/log/app --older-than 7d
s3vault upload /var/log/app/app.log --key logs/app.log
```

- `GET`/`HEAD /files/{path...}` — тот же prefix, что у archive; путь не длиннее 2048.
- `PUT /files/{path...}` — plaintext → identity/encrypt/Put на сервере; `201` uploaded, `200` identical skip, `204` policy omit (`on_change=skip`), `409` conflict (`on_change=fail`).
- `GET /health` — процесс жив (без токена).
- `GET /ready` — дешёвый HEAD в S3.
- Prometheus: отдельный `server.metrics_listen` (по умолчанию `127.0.0.1:9090`), путь `/metrics`. Без меток с полным path. На `archive`/`upload`/`download` тот же endpoint можно поднять на время команды через `--metrics-listen`.
- Кэш: каталог `0700`, файлы `0600`, id = SHA-256(bucket, key, etag, fingerprint ключей). `s3vault cache stats` / `cache clear`.
- Пустой `server.token` и bind не на loopback — процесс не стартует.

SIGTERM/SIGINT — graceful `Shutdown`.

## Дальше

Docker-образа и GitHub Actions ещё нет.
