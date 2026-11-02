# Пользователи gateway в PostgreSQL

**Версия:** 1.3. **Дата:** 2026-10-31. **Статус:** реализовано: реестры `s3vault_encryption_profiles`/`s3vault_targets`, ссылки из пользователей, CLI `target`/`profile`, per-request scope, пул целей, SSE-KMS/storage-class.

**Цель:** авторизовать клиентов S3-фасада шлюза по учётным записям в PostgreSQL и применять к каждому пользователю его собственный прозрачный префикс, ссылку на общий профиль шифрования и, при необходимости, ссылку на общий конечный S3.

**Не входит:** перешифровка существующих объектов, ротация мастер-ключа, несколько ключей/префиксов/профилей/конечных S3 на пользователя, роли и ACL сверх «все операции внутри префикса», квоты, rate limit, audit-таблица, кэш аутентификации, UI.

### Что изменилось в 1.3

- Профиль шифрования и конечный S3 — самостоятельные сущности с именами и неизменяемыми `uid`; пользователь ссылается на них, а не хранит копию.
- Один профиль/одна цель назначаются нескольким пользователям; изменение сущности действует на всех привязанных.
- Секрет цели хранится один раз в строке цели; AAD — `s3.secret_key:<target_uid>` / `s3.session_token:<target_uid>`.
- Одна миграция `001_users.sql` создаёт финальную схему: реестры профилей/целей и таблицу пользователей с FK. Backfill и legacy-колонки не нужны: схема ещё не накатывалась на стенды.
- CLI: `s3vault target ...`, `s3vault profile ...`; у `user` — `--s3-target`/`--encryption-profile`.
- `sse_kms` и `storage_class` остаются write-side параметрами цели.

---

## 1. Принятые решения

| Вопрос | Решение |
|---|---|
| Аутентификация | S3 SigV4: `access_key_id` + `secret_key`. Отдельного login-фронтенда нет. |
| Источник identity | Один на процесс: `server.auth.backend: static` или `postgres`. В `postgres` статические `server.s3_access_key/secret` запрещены. |
| Кардинальность | Один пользователь = один access key, один префикс, одна ссылка на профиль шифрования и необязательная одна ссылка на цель (`s3_target_uid`). Профиль и цель переиспользуются многими пользователями. |
| Секрет в БД | AES-256-GCM на уровне приложения; мастер-ключ только из env. Ротации мастер-ключа нет. |
| Префикс | Прозрачный: клиент работает с ключами без префикса. Префикс обязателен, уникален и не пересекается с другими. |
| Шифрование | Полная конфигурация в БД (`jsonb`). `NULL`/пустой `mode` — глобальный `encryption` шлюза. |
| Чтение при другом алгоритме | Fallback: сначала профиль пользователя, затем глобальный профиль шлюза, но только при несовпадении **алгоритма** (`none`/`native`/`command`). |
| Конечный S3 | Необязательная ссылка на общий `s3vault_targets`. `NULL` — глобальный `s3.*`; непустая — полная замена endpoint/bucket/prefix/region/path-style/кредов. Слияния с глобальным профилем нет. |
| Секреты конечного S3 | `secret_key` и `session_token` шифруются AES-256-GCM тем же мастер-ключом; отдельные колонки и AAD. |
| Store на пользователя | Ограниченный пул `ObjectStore` по fingerprint цели, а не создание store на каждый запрос. |
| Права | Все операции S3 в пределах префикса. Отдельных read-only/read-write флагов нет. |
| Lookup в БД | На каждый SigV4-запрос, без кэша. При 10 RPS это осознанный выбор: отзыв ключа действует сразу. |
| Недоступность БД | На старте — не стартовать. В рантайме — `503 ServiceUnavailable`, не `403`. |
| PostgreSQL | 18, без TLS (`sslmode=disable`), миграции применяются при старте. |
| Администрирование | CLI `s3vault user ...`. |
| Клиенты `archive`/`download` | Ходят в шлюз под S3-кредами пользователя. Отдельной логики БД у них нет. |
| Multipart и кэш | Сессия привязана к пользователю и профилю; кэш изолирован по пользователю. |
| E2E | Отдельный стенд с PostgreSQL. |

### 1.1 Решения, принятые без отдельного вопроса

- `server.s3_bucket_as_prefix` в `postgres`-режиме запрещён: префикс пользователя уже задаёт пространство имён, а второй слой `bucket/` сделал бы отображение ключей неоднозначным.
- Префиксы пользователей обязаны быть непересекающимися: `a` и `a/b` не могут принадлежать разным пользователям. Иначе пользователь `a` видел бы объекты `a/b`.
- Ключ вне префикса — `403 AccessDenied`. Для списка — молчаливое ограничение, без ошибки.
- Одинаковый алгоритм, но разные ключи (например, два `native` с разными `key_file`) fallback-ом не покрывается: fallback выбирается по имени алгоритма из `S3VCTR01`, а не повторной попыткой расшифровки тем же алгоритмом с другим ключом.
- `HEAD` объекта не расшифровывает тело и отдаёт метаданные, даже если `GET` этого объекта потом не сможет выбрать профиль. `GET` в таком случае отвечает `500 InternalError` с записью в лог.
- В `postgres`-режиме `server.s3_access_key`/`server.s3_secret_key` должны быть пустыми. Иначе шлюз не стартует: два источника identity в одном процессе запрещены.
- Конечный S3 — только в `postgres`-режиме: у static-пользователя нет строки БД и, следовательно, цели.
- Один и тот же профиль шифрования или одна и та же цель могут быть назначены нескольким пользователям. Это отдельные сущности в реестрах `s3vault_encryption_profiles` и `s3vault_targets`; пользователь хранит только `uid` ссылки. `target update`/`profile update` меняет сущность для всех привязанных, `user update` меняет ссылку у одной строки. Пул store'ов переиспользует один `ObjectStore` по fingerprint цели.
- Секрет цели хранится один раз в строке цели. AAD: `s3.secret_key:<target_uid>` и `s3.session_token:<target_uid>`. Переименование цели не требует перешифровки; перенос ciphertext в другую строку цели не расшифруется.
- Цель не сливается с глобальным `s3.*`: отсутствие любого поля — ошибка валидации, а не «взять глобальный». Это исключает отправку глобальных кредов на чужой endpoint.
- `sse_kms` и `storage_class` — необязательные write-side параметры цели. Если `sse_kms` отсутствует, шлюз не отправляет SSE-заголовки; если `storage_class` пуст, не отправляется `x-amz-storage-class`. Оба параметра входят в fingerprint цели (меняют поведение store'а), но не в namespace кэша (данные остаются там же).
- `target.prefix` применяется до пользовательского префикса: `target.prefix / user.prefix / client_key`. Глобальный `s3.prefix` для пользователя с целью не применяется.
- Смена цели не перешифровывает объекты и не переносит их. Старые ключи остаются в старом хранилище и через шлюз больше не адресуются.
- Цель не добавляет слой шифрования: шлюз по-прежнему обрамляет объект ровно один раз; меняется только место хранения.

---

## 2. Границы и точки изменения

### 2.1 Что не меняется

- Формат объекта: `S3VCTR01` + payload (`S3VLT01` для `native`) или контейнер `enc=0` для `none`. Шлюз по-прежнему **всегда обрамляет** свой слой (`service.Archive.WithFraming`).
- Статический режим (`server.auth.backend: static`) работает как сегодня: один principal из `server.s3_access_key/secret`.
- Клиентские команды `archive`, `upload`, `download` не знают о БД. Они указывают `s3.endpoint` на фасад и используют выданные пользователю S3-креды.
- Шифрование клиента и шифрование шлюза остаются двумя независимыми слоями. Профиль пользователя — это **слой шлюза**, а не замена клиентскому `encryption.mode`.
- Конечный S3 не меняет формат объекта и не добавляет слой: это только адрес хранения. Один и тот же объект, записанный через шлюз, одинаково обрамлён независимо от цели.
- S3 API: Get/Head/Put/Delete/ListV2/HeadBucket/ListBuckets и пять multipart-операций. `CopyObject`, `CreateBucket`, virtual-host в v1 отсутствуют.

### 2.2 Точки изменения

| Файл/пакет | Изменение |
|---|---|
| `internal/port/s3identity.go` | `Principal` получает `User UserPolicy`; `UserPolicy.Target *S3Target`; новые sentinel-ошибки `ErrAuthUnavailable`, `ErrAuthInternal`. |
| `internal/adapter/s3auth/postgres/` | Адаптер `port.S3Identity`: `postgres.go` (пул, миграция, стартовая валидация, `Ping`, `Close`), `identity.go` (`Lookup`, `Allow` по JOIN с реестрами), `admin.go` (`user ...`, ссылки на профиль/цель), `registry.go` (`target ...`, `profile ...`), `migrations/001_users.sql` (финальная схема). |
| `internal/adapter/s3target/` | Разбор и валидация профиля цели, `sse_kms`/`storage_class`, `Namespace`/`Fingerprint`, пул `ObjectStore` по fingerprint. |
| `internal/adapter/s3/store.go` | `NewWithOptions`: SSE-KMS и `x-amz-storage-class` только при заданных опциях цели. |
| `internal/adapter/s3auth/secretbox/` | AES-256-GCM для `secret_key` в БД; `ParseKey`/`Seal`/`Open`/`GenerateSecret`. |
| `internal/keying/` | `ValidateRelative`, `NormalizePrefix`, `NormalizeOptionalPrefix`, `PrefixesOverlap`, `JoinPrefix`; `Mapper.FromRequestPath` использует общий валидатор. |
| `internal/adapter/encrypt/profile.go`, `names.go` | Разбор JSON профиля шифрования, `Resolver`/`Profile`, построение `Primary`/`Fallback`, fingerprint набора профилей, общие имена `none`/`native`/`command`. |
| `internal/s3api/scope.go` | Per-request scope: префикс (глобальный или цели), mapper, `Archive`/`Fetch` view, resolved store, cache namespace, профиль и fingerprint цели. |
| `internal/s3api/handler.go`, `get.go`, `put.go`, `delete.go`, `list.go`, `multipart.go` | Обработчики работают через `scope`, а не через глобальные `a.keys`/`a.archive`/`a.fetch`. |
| `internal/s3api/auth.go` | Маппинг новых ошибок: `503`, `500`, `403`. |
| `internal/s3api/s3err/error.go` | Новый код `ServiceUnavailable` (`503`). |
| `internal/s3api/session/registry.go` | Сессия хранит `UserID`, `ClientKey`, `Prefix`, `ProfileFingerprint`, `TargetFingerprint`; `GetForWrite` проверяет их, `GetForOwner` (access key + client key) обслуживает abort/list parts. |
| `internal/service/archive.go` | `WithProfile(keys, enc)` — view с другими ключами и шифратором; `WithStore(store)` — view с другим конечным S3. |
| `internal/service/fetch.go` | `WithProfile(primary, fallback, cacheBucket, fp)` и `WithStore(store, namespace)`; `reval` становится указателем, чтобы view не копировал mutex; `servedEntry` закрывает гонку sidecar. |
| `internal/service/fetch_profile.go` | `encryptorFor`, `legacyEncryptor`, `decryptStream`: выбор primary/fallback и legacy-классификация по magic. |
| `internal/cli/root.go` | Сборка identity по `server.auth.backend`; `encrypt.NewResolver`; пул целей и `s3api.Config.Targets`; `ReadyCheck`; регистрация `target`/`profile`. |
| `internal/cli/user.go` | Команды `user add/list/update/rotate/disable/enable`; `--encryption-profile`/`--s3-target` и `--clear-*`. |
| `internal/cli/target.go`, `profile.go` | Команды `target add/list/update/remove`, `profile add/list/update/remove`; чтение профилей из файла/stdin. |
| `internal/config/config.go` | Секция `server.auth`, env-ключи, `normalizeAuth`, параметры пула целей, `S3APIEnabled`. |
| `internal/httpserver/server.go` | `ReadyCheck func(context.Context) error`; `/ready` вызывает его после проверки хранилища. |
| `internal/*_test.go`, `internal/s3api/facade_postgres_integration_test.go` | Unit- и integration-покрытие; `//go:build integration` для PostgreSQL. |
| `README.md`, `architecture.md`, `s3vault.example.yaml`, `.env.example`, `compose.e2e.yaml`, `scripts/e2e.sh`, `.github/workflows/` | Документация, примеры, E2E-стенд, CI. |
| `go.mod` | `github.com/jackc/pgx/v5` (+ `pgxpool`, `puddle`, `pgpassfile`, `pgservicefile`). |

---

## 3. Схема БД

### 3.1 Реестры и таблица пользователей

Пользователь хранит только ссылки на общие сущности. Итоговая схема:

```sql
CREATE TABLE s3vault_encryption_profiles (
    uid        text        PRIMARY KEY,          -- 32 hex, неизменяемый
    name       text        NOT NULL,
    config     jsonb       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT s3vault_encryption_profiles_name_key UNIQUE (name),
    CONSTRAINT s3vault_encryption_profiles_uid_len
        CHECK (octet_length(uid) = 32),
    CONSTRAINT s3vault_encryption_profiles_name_nonempty
        CHECK (name <> ''),
    CONSTRAINT s3vault_encryption_profiles_config_object
        CHECK (jsonb_typeof(config) = 'object')
);

CREATE TABLE s3vault_targets (
    uid                text        PRIMARY KEY,  -- 32 hex, неизменяемый, входит в AAD
    name               text        NOT NULL,
    config             jsonb       NOT NULL,     -- несекретная часть профиля цели
    secret_nonce       bytea       NOT NULL,
    secret_ciphertext  bytea       NOT NULL,
    session_nonce      bytea,
    session_ciphertext bytea,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT s3vault_targets_name_key UNIQUE (name),
    CONSTRAINT s3vault_targets_uid_len
        CHECK (octet_length(uid) = 32),
    CONSTRAINT s3vault_targets_name_nonempty
        CHECK (name <> ''),
    CONSTRAINT s3vault_targets_config_object
        CHECK (jsonb_typeof(config) = 'object'),
    CONSTRAINT s3vault_targets_config_no_plaintext_secret
        CHECK (NOT (config ? 'secret_key') AND NOT (config ? 'session_token')),
    CONSTRAINT s3vault_targets_secret_nonce_len
        CHECK (octet_length(secret_nonce) = 12),
    CONSTRAINT s3vault_targets_secret_ciphertext_len
        CHECK (octet_length(secret_ciphertext) > 16),
    CONSTRAINT s3vault_targets_session_pair
        CHECK ((session_nonce IS NULL) = (session_ciphertext IS NULL)),
    CONSTRAINT s3vault_targets_session_nonce_len
        CHECK (session_nonce IS NULL OR octet_length(session_nonce) = 12),
    CONSTRAINT s3vault_targets_session_ciphertext_len
        CHECK (session_ciphertext IS NULL OR octet_length(session_ciphertext) > 16)
);

CREATE TABLE s3vault_users (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                  text        NOT NULL,
    access_key_id         text        NOT NULL,
    secret_key_nonce      bytea       NOT NULL,
    secret_key_ciphertext bytea       NOT NULL,
    prefix                text        NOT NULL,
    encryption_profile_uid text,
    s3_target_uid         text,
    enabled               boolean     NOT NULL DEFAULT true,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT s3vault_users_name_key        UNIQUE (name),
    CONSTRAINT s3vault_users_access_key_key  UNIQUE (access_key_id),
    CONSTRAINT s3vault_users_prefix_key      UNIQUE (prefix),
    CONSTRAINT s3vault_users_access_key_nonempty
        CHECK (access_key_id <> ''),
    CONSTRAINT s3vault_users_prefix_nonempty
        CHECK (prefix <> ''),
    CONSTRAINT s3vault_users_nonce_len
        CHECK (octet_length(secret_key_nonce) = 12),
    CONSTRAINT s3vault_users_ciphertext_len
        CHECK (octet_length(secret_key_ciphertext) > 16),
    CONSTRAINT s3vault_users_encryption_profile_fkey
        FOREIGN KEY (encryption_profile_uid)
        REFERENCES s3vault_encryption_profiles(uid) ON DELETE RESTRICT,
    CONSTRAINT s3vault_users_s3_target_fkey
        FOREIGN KEY (s3_target_uid)
        REFERENCES s3vault_targets(uid) ON DELETE RESTRICT
);
```

`NULL` в `encryption_profile_uid`/`s3_target_uid` = глобальный профиль/глобальный S3.

`uid` — случайные 16 байт в hex, генерируются приложением. Имя изменяемое; `uid` — нет. `ON DELETE RESTRICT` не даёт удалить используемую сущность.

`prefix` хранится в каноническом виде: без ведущего/замыкающего `/`, без пустых сегментов, без `.` и `..`, с `/` как разделителем. Проверка каноничности и непересечения — в приложении (CLI + старт), а не в SQL: `UNIQUE` ловит только точное совпадение, но не `a` vs `a/b`.

`updated_at` обновляется приложением (`SET updated_at = now()`), триггеров нет.

### 3.1.1 Миграция

Схема создаётся одной миграцией `001_users.sql`: реестры профилей/целей и таблица пользователей с FK. Ранее существовавшие legacy-колонки (`encryption`, `s3_target`, `s3_secret_*`, `s3_session_*`) в этой ветке не создаются, поэтому backfill не нужен: миграции ещё не накатывались на стенды. Если схема уже была создана старой веткой, её нужно пересоздать (вне scope мигратора).

### 3.2 JSON профиля шифрования

Профиль — строка `s3vault_encryption_profiles`; пользователь ссылается на неё через `encryption_profile_uid`, а `NULL` означает глобальный `encryption` шлюза. Профиль всегда полный, без слияния с глобальным; `{}`, `null` и пустой `mode` в реестр не записываются (это «глобальный»):

```json
{
  "mode": "native",
  "native": {
    "wrap": "rsa-oaep",
    "public_key_path": "/etc/s3vault/users/alice/public.pem",
    "private_key_path": "/etc/s3vault/users/alice/private.pem",
    "key_file": "",
    "chunk_size": 65536
  },
  "command": {
    "encrypt": ["/usr/local/bin/cryptcp-wrapper", "encrypt"],
    "decrypt": ["/usr/local/bin/cryptcp-wrapper", "decrypt"],
    "provider": "cryptopro",
    "thumbprint": "afa43c43975fbfc700f051fd62016e1571e7e025",
    "timeout": "30m"
  }
}
```

Правила разбора:

- `mode` задаёт профиль; в реестре `mode` обязателен и должен быть одним из `none`, `native`, `command` (регистр нормализуется). «Глобальный профиль» — это отсутствие ссылки (`encryption_profile_uid IS NULL`), а не пустой mode.
- Неизвестные поля отвергаются (`DisallowUnknownFields`).
- `native.wrap`: `rsa-oaep` (по умолчанию) или `keyfile`.
  - `rsa-oaep`: обязателен `private_key_path` (для чтения); `public_key_path` опционален, потому что публичная часть выводится из приватной.
  - `keyfile`: обязателен `key_file`.
  - `chunk_size`: по умолчанию `65536`; допустимый диапазон — `config.MinNativeChunkSize`..`config.MaxNativeChunkSize`.
- `command`: обязательны непустые `encrypt` и `decrypt`; первый элемент argv непустой; `provider` по умолчанию `cryptopro`; `thumbprint` обязателен и нормализуется; `timeout` — строка Go duration, по умолчанию `30m`.
- Для `mode=none` ключевые поля игнорируются.
- Пути к ключам — абсолютные, указывают на обычные файлы; приватный ключ/`key_file` должны быть доступны процессу шлюза. Секреты (PIN, пароли) в `encrypt`/`decrypt` argv не допускаются — только через env, как и в существующем `command`-режиме.
- Сборка профиля выполняется тем же `encrypt.New`, что и глобальный конфиг, поэтому формат и ограничения ключей не дублируются.

### 3.3 Миграции

- Встроенная миграция `001_users.sql` в `internal/adapter/s3auth/postgres/migrations/`.
- Таблица версий: `s3vault_schema_migrations(version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`.
- Миграции применяются автоматически при открытии БД в `server` и в `s3vault user/target/profile ...`.
- `Open` держит `pg_advisory_lock` на всё время применения миграций; это защищает от гонки нескольких реплик/CLI.
- Миграции только `up`; отката в v1 нет.
- Внешняя библиотека миграций не вводится: четыре миграции и таблица версий проще `golang-migrate`/`goose`.

### 3.4 Зависимость pgx

Добавляется `github.com/jackc/pgx/v5` (+ `pgxpool`): нативный протокол PostgreSQL, контекстные запросы, таймауты и пул без слоя `database/sql` и без ORM. `lib/pq` не выбран (maintenance-only), `database/sql` + `pgx/stdlib` добавил бы лишний слой без выгоды. Других новых зависимостей нет: AES-GCM — stdlib, миграции — встроенный SQL + advisory lock.

---

## 4. Секреты

`secret_key` нужен шлюзу в открытом виде для проверки SigV4, поэтому хеширование невозможно.

- Мастер-ключ: `S3VAULT_SERVER_AUTH_MASTER_KEY`, base64 от ровно 32 байт. Читается напрямую из env, не из YAML; в конфиг-файл не попадает.
- Шифр: AES-256-GCM, случайный 12-байтовый nonce на каждую запись.
- AAD: `access_key_id` в байтах. Ciphertext, скопированный в другую строку, не расшифруется.
- В БД: `secret_key_nonce` (12 байт) и `secret_key_ciphertext` (ciphertext + 16-байтовый tag).
- `user add` и `user rotate` генерируют секрет (`crypto/rand`, 30 байт, base64 RawURLEncoding) и печатают его **один раз** в stdout. Секрет никогда не принимается аргументом командной строки и не пишется в лог.
- Ротации мастер-ключа нет. Смена `S3VAULT_SERVER_AUTH_MASTER_KEY` делает все секреты нечитаемыми; для смены нужна offline-перешифровка (вне scope).
- Ошибка расшифровки секрета — `ErrAuthInternal` → `500`, запись в лог без ciphertext и без секрета.

Секреты конечного S3 (`secret_key`, `session_token`) защищены тем же мастер-ключом, но лежат в строке цели `s3vault_targets` и имеют собственный AAD:

- `secret_nonce` + `secret_ciphertext` — `secret_key` цели;
- `session_nonce` + `session_ciphertext` — `session_token` цели; пустой токен хранится как `NULL`, а не как зашифрованная пустая строка (иначе `ciphertext = 16` не проходит constraint `> 16`);
- AAD: `s3.secret_key:<target_uid>` и `s3.session_token:<target_uid>`.

`target_uid` — неизменяемый случайный идентификатор, поэтому переименование цели не требует перешифровки. Ciphertext нельзя переставить ни в другую строку цели, ни в другую колонку. Прямая SQL-правка `uid` делает секреты нечитаемыми, и старт падает.

`secret_key`/`session_token` цели **никогда** не попадают в `config jsonb`, в `target list`/`user list`, в логи или в argv. Их принимает только файл/stdin при `target add`/`target update`.

---

## 5. Конфигурация

```yaml
server:
  auth:
    backend: postgres        # static | postgres; по умолчанию static
    dsn: ""                  # предпочтительно env S3VAULT_SERVER_AUTH_DSN
    max_conns: 8
    query_timeout: 2s
    target_pool_max: 64      # максимум ObjectStore для пользовательских целей
    target_pool_idle: 15m    # простой, после которого store вытесняется
```

| Ключ | Default | Смысл |
|---|---|---|
| `server.auth.backend` | `static` | `static` — текущий один principal; `postgres` — пользователи из БД. |
| `server.auth.dsn` | — | PostgreSQL DSN. В `postgres` обязателен. Пароль лучше передавать через env. |
| `server.auth.max_conns` | `8` | `pgxpool.MaxConns`; `0` → default, отрицательное — ошибка. |
| `server.auth.query_timeout` | `2s` | Таймаут одного `Lookup`; `0` → default, отрицательное — ошибка. |
| `server.auth.target_pool_max` | `64` | Максимум store'ов в пуле целей; `0` → default, отрицательное — ошибка. |
| `server.auth.target_pool_idle` | `15m` | Простой цели до вытеснения; `0` → default, отрицательное — ошибка. |
| `S3VAULT_SERVER_AUTH_MASTER_KEY` | — | Env-only, base64 32 байта. Обязателен в `postgres`. |

Пример DSN для стенда: `postgres://s3vault@127.0.0.1:5432/s3vault?sslmode=disable`. Если в будущем понадобится TLS, он задаётся через `sslmode` в DSN; отдельного ключа нет.

Валидация в `config.Normalize`:

- `backend` нормализуется и должен быть `static` или `postgres`.
- `postgres`: `dsn` непустой; `server.s3_bucket_as_prefix` = `false`; `server.s3_access_key` и `server.s3_secret_key` пустые.
- `static`: поведение не меняется.
- `target_pool_max`/`target_pool_idle`: `0` → default, отрицательное — ошибка; параметры действуют только при наличии целей.
- `ServerConfig.S3APIEnabled()` возвращает `true` для `postgres` без статических ключей; для `static` — только когда оба ключа заданы.
- `httpserver.requireS3API` продолжает проверять наличие handler, но текст ошибки обновляется: допустимы либо static-ключи, либо `auth.backend=postgres`.

`S3VAULT_SERVER_AUTH_MASTER_KEY` не является полем `Config` и не попадает в `envKeys`: это секрет, который читают только команды, открывающие БД (`server`, `user`). `TestEnvKeysMatchConfigFields` не затрагивается.

---

## 6. Старт, readiness, отказ БД

### 6.1 Старт `server`

1. `config.Load` + `Normalize`.
2. `encrypt.New(cfg.Encryption)` — глобальный профиль (он же fallback); из него же строится `encrypt.NewResolver(cfg.Encryption)` для `s3api.Config.Profiles`.
3. `newObjectStore` — глобальный store (он же default для всех пользователей без цели).
4. Identity:
   - `static`: `&s3auth.Static{...}` как сейчас.
   - `postgres`: `postgresauth.Open(ctx, Config{DSN, MaxConns, QueryTimeout, MasterKey, Bucket, Logger, ValidateEncryption})`.
5. `Open` в `postgres`:
   - парсит DSN, создаёт `pgxpool` (`application_name=s3vault`, `ConnectTimeout=5s`, `MaxConnLifetime=30m`, `MaxConnIdleTime=5m`, `HealthCheckPeriod=1m`, `MaxConns` из конфига);
   - `Ping` с таймаутом 5s;
   - применяет миграции под advisory lock (simple protocol для многооператорного SQL);
   - проводит стартовую валидацию (см. 6.3), используя переданный `ValidateEncryption` и `s3target.Validate`, если не выставлен `SkipValidation`; CLI управления выставляет его, чтобы битая строка не блокировала list/remove;
   - возвращает `*postgresauth.Identity`.
6. В `postgres`-режиме создаётся `s3target.Pool` с builder'ом `s3store.NewWithOptions` (SSE-KMS/storage-class из цели) и лимитами `server.auth.target_pool_*`; он передаётся в `s3api.Config.Targets`. Пул не открывает соединений и не строит store'ы при старте; первый store появляется на первом запросе пользователя с целью.
7. Любая ошибка `Open` — шлюз **не стартует**.
8. `server` передаёт в `httpserver.Config` дополнительный `ReadyCheck` — `identity.Ping`, если backend `postgres`.

Порядок `defer` гарантирует закрытие пула целей и `pgxpool` после остановки HTTP-сервера.

### 6.2 Readiness

- `/health` — liveness, всегда `200`, как сейчас.
- `/ready` — проверка глобального хранилища (`store.Head(".s3vault-ready")`) и, в `postgres`-режиме, `pool.Ping`.
- Любая из проверок не прошла — `503`.
- В `static`-режиме `ReadyCheck` отсутствует, поведение прежнее.
- `/ready` **не** проверяет пользовательские цели: их может быть много, и недоступность одного бэкенда не должна выводить из ротации весь шлюз. Отказ цели виден только запросам этого пользователя (`5xx` + лог). Для мониторинга целей нужен внешний пробник на конкретный endpoint/bucket.

### 6.3 Стартовая валидация БД

Под тем же advisory lock, что и мутации пользователей:

- реестр профилей читается целиком: `uid`, `name`, `config`; `config` непустой (не `{}`/пустой mode) и собирается `encrypt.NewResolver(...).ResolveRaw` (проверяются пути к ключам);
- реестр целей читается целиком: `uid`, `name`, `config`, `secret_nonce`, `secret_ciphertext`, `session_nonce`, `session_ciphertext`; `config` разбирается и проходит `s3target.Validate` (значения канонические); секреты расшифровываются мастер-ключом с AAD `target_uid`. Цель **не** проверяется сетевым запросом: bucket может быть создан позже, а старт не должен зависеть от N чужих S3;
- пользователи читаются: `id`, `access_key_id`, `prefix`, `secret_key_nonce`, `secret_key_ciphertext` (disabled-пользователи тоже проверяются);
- `access_key_id` непустой и уникальный (гарантируется SQL);
- `prefix` канонический, непустой;
- префиксы попарно не пересекаются (сегментно: `a` и `a/b` — пересечение);
- `secret_key_ciphertext` расшифровывается мастер-ключом (проверяется, что мастер-ключ подходит);
- ссылки `encryption_profile_uid`/`s3_target_uid` существуют (гарантируется FK).

Любая ошибка — отказ старта с сообщением, называющим сущность (`name`/`uid`) или `access_key_id` и причину (без секрета). Стоимость O(профилей + целей + пользователей); при малом стенде это приемлемо и даёт fail-fast.

Шлюз всегда валидирует реестры при старте. CLI `user`/`target`/`profile` для list/remove/disable и обновлений, не перешифровывающих секреты, открывает `Open(..., SkipValidation: true)`: одна битая строка не должна лишать оператора возможности её увидеть и удалить. Команды, создающие или перезапечатывающие секрет (`user add/rotate`, `target add/update`, `profile add/update`), по-прежнему идут через полную валидацию, чтобы неверный мастер-ключ не был пропущен.

### 6.4 Ошибки БД в рантайме

- `Lookup` при ошибке соединения/запроса/таймаута возвращает `port.ErrAuthUnavailable`.
- `mapAuthError` маппит его в `s3err.ServiceUnavailable` (`503`), результат метрики `unavailable`.
- `403 AccessDenied` при недоступной БД **не** отдаётся: клиент не должен принимать инфраструктурную ошибку за отказ в правах.
- Кэша, который мог бы продолжить работу при упавшей БД, нет. Это осознанный fail-closed.

---

## 7. Поток аутентификации и авторизации

### 7.1 `Lookup`

```sql
SELECT u.id, u.access_key_id, u.secret_key_nonce, u.secret_key_ciphertext,
       u.prefix, u.enabled,
       p.uid, p.config,
       t.uid, t.name, t.config,
       t.secret_nonce, t.secret_ciphertext,
       t.session_nonce, t.session_ciphertext
FROM s3vault_users u
LEFT JOIN s3vault_encryption_profiles p ON p.uid = u.encryption_profile_uid
LEFT JOIN s3vault_targets t ON t.uid = u.s3_target_uid
WHERE u.access_key_id = $1;
```

- Нет строки → `(Principal{}, false, nil)`; `credProvider` отдаёт `awsig.ErrInvalidAccessKeyID`.
- `enabled = false` → `port.ErrAccessDenied`; `Provide` возвращает ошибку, `mapAuthError` маппит её в `403 AccessDenied`. Подпись при этом не проверяется, но доступа к данным всё равно нет.
- Ошибка БД/таймаут → `port.ErrAuthUnavailable`.
- Ошибка расшифровки секрета → `port.ErrAuthInternal`.
- Ошибка/невалидность цели в `s3vault_targets` → `port.ErrAuthInternal` (500): строка БД испорчена, это не отказ в правах.
- Успех → `Principal`:
  ```go
  type S3Target struct {
      Endpoint     string
      Region       string
      Bucket       string
      Prefix       string
      AccessKey    string
      SecretKey    string // never log
      SessionToken string // never log
      PathStyle    bool
  }

  type UserPolicy struct {
      ID         int64
      Prefix     string
      Encryption json.RawMessage // nil = глобальный профиль
      Target     *S3Target       // nil = глобальный s3.*
  }

  type Principal struct {
      AccessKeyID    string
      SecretKey      string
      AllowedBuckets []string
      User           UserPolicy
  }
  ```
  `Target` собирается из строки `s3vault_targets` + расшифрованных `secret_*`/`session_*`; `Lookup` повторно валидирует его (защита от прямых SQL-правок). Static-адаптер оставляет `User` нулевым.

`Lookup` выполняется на каждый SigV4-запрос; кэша нет. Изменения в БД (disable, rotate, смена префикса/профиля/цели) видны со следующего запроса.

### 7.2 `Allow`

`Allow` работает только в памяти, без БД:

- `S3OpListBuckets` — разрешено;
- `S3OpHeadBucket`, `S3OpList` — только виртуальный bucket;
- Get/Head/Put/Delete и все multipart-операции — только виртуальный bucket и непустой относительный ключ;
- ключ проверяется общим `keying.ValidateRelative` (нет `\`, NUL, ведущего `/`, `.`/`..`, выхода за корень);
- `User.ID != 0` и `User.Prefix` канонический непустой; иначе `port.ErrAccessDenied`;
- любой неизвестный `S3Op` — `port.ErrAccessDenied`.

Проверка «ключ внутри префикса» не дублируется здесь: префикс прозрачный, и клиентский ключ всегда относителен. Вхождение обеспечивает `scope` при отображении ключа. `Allow` лишь не пропускает ключи, которые могут выйти за корень.

### 7.3 Per-request scope

`scope` строится после успешного `Allow` и живёт один запрос:

```go
type scope struct {
    principal   port.Principal
    target      *port.S3Target // principal.User.Target; nil = глобальный S3
    keys        keying.Mapper  // (target.prefix | s3.prefix) + user.prefix
    cacheBucket string

    store   port.ObjectStore   // разрешается лениво
    profile *encrypt.Profile   // разрешается лениво
    archive *service.Archive
    fetch   *service.Fetch
}
```

- `basePrefix = api.keys.Prefix` для пользователя без цели; `basePrefix = target.Prefix` для пользователя с целью. Глобальный `s3.prefix` в этом случае не участвует.
- `combinedPrefix = keying.JoinPrefix(basePrefix, principal.User.Prefix)`.
- `keys = keying.Mapper{Prefix: combinedPrefix}` — единственная точка отображения клиентских ключей. `bucketAsPrefix` в `postgres` не используется.
- `cacheBucket = api.bucketBackend`; для DB-пользователя `cacheBucket += "|user:" + id`; при наличии цели дополнительно `"|s3:" + s3target.Namespace(target)`. Для пользователей без цели строка не меняется — старые cache id остаются валидными после обновления.
- `storeFor(ctx)` возвращает `api.store` при `target == nil`, иначе — store из `api.targets` (пул). Ошибка разрешения — `500` и запись в лог; в `Delete` store нужен до удаления, поэтому ошибка возвращается клиенту.
- `targetNamespace` = `""` при `target == nil`, иначе `s3target.Namespace(*target)`; входит в `cacheBucket` и в ключ `ephemeralSet`.
- `targetFingerprint()` = `""` при `target == nil`, иначе `s3target.Fingerprint(*target)`; используется только снимком multipart-сессии и не требует построения store.
- `profile` разрешается **лениво**, при первом обращении операции, которой нужно шифрование:
  - `PutObject`, `GetObject`, `HeadObject`, `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`;
  - `DeleteObject` — только для best-effort инвалидации кэша, если он включён;
  - `ListObjectsV2`, `ListBuckets`, `HeadBucket`, `AbortMultipartUpload`, `ListParts` профиль не разрешают и не падают из-за сломанного ключевого файла.
- `store` разрешается **лениво** и только теми операциями, которые реально ходят в хранилище:
  - `Get`, `Head`, `Put`, `Delete`, `List`, `CompleteMultipartUpload`;
  - `CreateMultipartUpload`, `UploadPart` берут только fingerprint цели для снимка сессии, store не строят;
  - `HeadBucket`, `ListBuckets`, `AbortMultipartUpload`, `ListParts` не разрешают ни store, ни профиль.
- `archiveFor(ctx)` возвращает `api.archive.WithStore(store).WithProfile(keys, profile.Primary)`; `fetchFor(ctx)` — `api.fetch.WithStore(store, targetNamespace).WithProfile(profile.Primary, profile.Fallback, cacheBucket, profile.Fingerprint)`.
- `profile` — результат `api.profiles.ResolveRaw(principal.User.Encryption)` (см. §9); `api.profiles *encrypt.Resolver`.
- `cacheFingerprint(ctx)` возвращает `api.encFP` для static и `profile.Fingerprint` для DB; `invalidateCache` использует `cacheBucket` + fingerprint.
- Для `static` (`User.ID == 0`) `archiveFor`/`fetchFor` возвращают глобальные `api.archive`/`api.fetch`, `storeFor` — `api.store`, а `keys` равен глобальному mapper; поведение не меняется.
- `List` и `Delete` больше не используют `a.store` напрямую: они берут store из `scope.storeFor(ctx)`.

Все обработчики (`get`, `put`, `delete`, `list`, `multipart`) получают `*scope` и не обращаются к глобальным `a.keys`/`a.archive`/`a.fetch`/`a.store`/`a.encFP`.

---

## 8. Префикс

### 8.1 Формат и инварианты

- Непустой; канонический: `tenant-a`, `tenant-a/logs`, без ведущего/замыкающего `/`, без `//`, `.` и `..`.
- Регистрозависимый (S3-ключи регистрозависимы).
- Уникален; префиксы разных пользователей не пересекаются сегментно.
- `NormalizePrefix` обрезает внешние пробелы и `/`, затем отвергает пустые сегменты, `.`, `..`, `\`, NUL.
- `PrefixesOverlap(a, b)` = `a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")`.
- Проверка выполняется:
  - `user add` / `user update` — под advisory lock мутаций;
  - при старте — по всем строкам;
  - прямые SQL-правки без CLI не поддерживаются.

### 8.2 Отображение ключей

- Клиент: `GET /bucket/report.pdf`.
- Backend без цели: `s3.prefix / user.prefix / report.pdf`.
- Backend с целью: `target.prefix / user.prefix / report.pdf`; глобальный `s3.prefix` не применяется, `target.bucket` — это реальный bucket в целевом хранилище, а не виртуальный bucket клиента.
- Обратное отображение для List: срезать `(target.prefix | s3.prefix)/user.prefix/` (и bucket-сегмент, если бы он был; в `postgres` его нет).
- Клиентские ключи всегда относительны префикса. Если клиент пришлёт `tenant-a/report.pdf`, получится `tenant-a/tenant-a/report.pdf`; это не ошибка безопасности, но документируется как неверное использование.
- Traversal (`..`, `%2e%2e`, ведущий `/`, `\`) отвергается до склейки. `keying.Mapper.FromRequestPath` валидирует `rel` **до** `path.Join`, поэтому `../x` не может выйти из префикса.

### 8.3 ListObjectsV2

- `prefix` клиента склеивается с `(target.prefix | s3.prefix)/user.prefix`; пустой клиентский prefix означает эту комбинацию с замыкающим `/`. Замыкающий `/` сохраняется (S3 prefix — строковый, а не путь).
- `start-after` отображается тем же mapper'ом (это также исправляет существующий баг с `s3.prefix`).
- `continuation-token` в `postgres`-режиме — base64url от backend-токена; клиент не видит префикс. В `static`-режиме токен остаётся прежним.
- `Contents[].Key`, `CommonPrefixes[].Prefix` срезаются до клиентского вида.
- `Prefix`, `StartAfter`, `NextContinuationToken` в ответе — в клиентском виде.
- `delimiter`, `max-keys`, `KeyCount`, `IsTruncated` — без изменений.
- Некорректный `continuation-token` → `400 InvalidRequest`; некорректный `prefix`/`start-after` → `403 AccessDenied`.
- Если backend вернул ключ вне scope (не должно случаться), он пропускается с `WARN`, а не отдаётся клиенту.

### 8.4 Остальные операции

- `HeadBucket`/`ListBuckets` возвращают один виртуальный bucket (`server.s3_bucket` или `s3.bucket`, иначе `s3vault`); цель на них не влияет.
- `Get`/`Head`/`Put`/`Delete`/`List`/multipart используют `scope.keys` и `scope.storeFor`.
- `Delete` удаляет только объект в префиксе и только в текущей цели; вне префикса — `403`.
- `ListParts`/`AbortMultipartUpload` работают по `accessKeyID` + `clientKey` сессии, поэтому доступны даже после смены префикса/профиля (см. §11).

---

## 9. Шифрование

Конечный S3 (§19) ортогонален шифрованию: выбор `Primary`/`Fallback` зависит только от `encryption` и `S3VCTR01.enc`, а не от endpoint/bucket цели. Один и тот же профиль шифрования работает с любой целью.

### 9.1 Write

- Профиль пользователя (или глобальный, если `encryption_profile_uid IS NULL`) — **primary**.
- `PutObject` передаёт в `scope.archive` клиентский ключ (`ExplicitKey`); комбинированный `(target.prefix | s3.prefix)/user.prefix` добавляет mapper ровно один раз.
- `Archive` пишет слой шлюза с `S3VCTR01`, где `enc`/`wrap`/`provider`/`thumbprint` берутся из primary.
- `mode=none` пишет контейнер `enc=0` (шлюз всегда обрамляет).
- Клиентский слой не трогается: если клиент прислал `S3VCTR01`, шлюз шифрует его как payload и добавляет свой внешний слой.
- Ошибка сборки профиля (нет файла ключа, невалидный argv) → `500 InternalError`, запись в лог; объект не пишется.

### 9.2 Read

`Fetch` получает `primary` и `fallback` (fallback — глобальный профиль, только если его `mode` отличается от primary); выбор делает `Fetch.encryptorFor`/`Fetch.legacyEncryptor`, а поток читает `Fetch.decryptStream`:

- `S3VCTR01.enc == "none"` — читается **всегда** через `Passthrough` (это не шифрование; доступ ограничен префиксом).
- `enc == primary.Name()` — primary.
- иначе `enc == fallback.Name()` — fallback.
- иначе — `500 InternalError` с сообщением, какие профили доступны; ciphertext как plaintext не отдаётся.

Fallback — только по имени алгоритма. Если оба профиля `native`, но с разными ключами, объект читается primary; ошибка ключа не приводит к повторной попытке fallback. Это ограничение документируется.

Containerless (legacy) объекты в `postgres`-режиме классифицируются по magic:

- `S3VLT01` → native-профиль (primary или fallback);
- `Salted__` → command-профиль (primary или fallback);
- иначе plaintext → `Passthrough` (читается любым профилем).

Если нужного профиля нет — явная ошибка. `command` больше не запускается на заведомо plaintext-объекте. В `static`-режиме сохраняется текущая логика `DecryptAuto`/`decryptLegacy`.

`HEAD` в общем случае не расшифровывает тело: `Fetch.Stat` отдаёт метаданные из `S3VCTR01`/HEAD. Поэтому `HEAD` может успешно ответить там, где `GET` вернёт `500` из-за отсутствия профиля. Исключение — legacy-объект без контейнера и без объявленного размера: там `Stat` материализует объект, чтобы узнать длину plaintext, и профиль уже нужен. Это осознанно: HEAD — метаданные, а не чтение.

### 9.3 Профили и fingerprint

`encrypt.Resolver` (конкретный тип в `internal/adapter/encrypt`, передаётся в `s3api.Config.Profiles`):

```go
type Profile struct {
    Primary     port.Encryptor
    Fallback    port.Encryptor // nil, если режимы совпадают
    Fingerprint string
}

type Resolver struct {
    defaultEnc port.Encryptor
    defaultFP  string
}
```

- `Resolver.ResolveRaw(nil)` / `ResolveRaw({})` / `ResolveRaw({"mode":""})` → глобальный профиль, `Fingerprint = encrypt.Fingerprint(cfg.Encryption)`.
- `Resolver.ResolveRaw(raw)` → строгий разбор JSON (`DisallowUnknownFields`), `encrypt.New`, `encrypt.Fingerprint`.
- `Fallback` = глобальный `Primary`, если `primary.Name() != global.Name()`, иначе `nil`.
- `Fingerprint`:
  - fallback нет → `primaryFP`;
  - fallback есть → `hex(sha256(primaryFP || 0x00 || fallbackFP))`.
- Профиль собирается на каждый запрос, без кэша. При 10 RPS это дешевле, чем продумывать инвалидацию при изменении файлов ключей; при необходимости позже добавляется кэш по fingerprint.
- `encrypt.Name(port.Encryptor)` — helper (`none`/`native`/`command`) для выбора и сообщений; имена вынесены в `internal/adapter/encrypt/names.go`.

### 9.4 Смена профиля и существующие объекты

- Перешифровки нет. После смены профиля старые объекты могут стать нечитаемыми.
- Если старый объект имеет **другой** алгоритм и глобальный профиль его покрывает — сработает fallback.
- Если алгоритм тот же, но ключи другие — объект не читается; это не fallback-случай.
- `user update --encryption-profile`, `--prefix`, `--s3-target` и их `--clear-*` требуют `--force`; `target update`/`profile update` тоже требуют `--force` и печатают число затронутых пользователей.

---

## 10. Кэш plaintext

- Кэш остаётся опциональным (`cache.enabled`, по умолчанию `false`); DB-режим работает и без него.
- `cacheBucket` для DB-пользователя: `CacheNamespace() + "|user:" + id`; при наличии цели добавляется `"|s3:" + s3target.Namespace(target)`. Даже при одинаковом backend-ключе два пользователя не могут получить чужой plaintext, а пользователь с целью — plaintext из глобального S3.
- `Namespace` цели включает все несекретные поля, определяющие **место** данных (`endpoint`, `region`, `bucket`, `prefix`, `path_style`, `access_key`), но не `secret_key`/`session_token` и не write-side параметры `sse_kms`/`storage_class`: смена секрета или SSE/класса не инвалидирует кэш, потому что данные лежат там же. `access_key` входит, чтобы две разные учётные записи на одном endpoint с одинаковым именем bucket не делили кэш. `Fingerprint` (с хэшами секретов и write-side параметрами) для кэша не используется.
- `encFP` = `Profile.Fingerprint` (primary + fallback). Смена профиля/глобального fallback меняет id и не отдаёт старую расшифровку.
- `Put`/`Delete`/`CompleteMultipartUpload` инвалидируют запись по `cacheBucket` + `cacheFP` scope. Для `Delete` инвалидация best-effort: если профиль не разрешился, ошибка пишется в лог, а удаление не отменяется.
- `Fetch.WithStore(store, namespace)` заменяет store и добавляет namespace к ключу `ephemeralSet`; `Fetch.WithProfile` делит с глобальным `Fetch`:
  - `cache`, `spoolDir`, `metrics`, `logger`;
  - `eph *ephemeralSet` (ключ — `namespace + "\x00" + backend-ключ`; пустой namespace сохраняет прежний ключ);
  - `reval *singleflight.Group` (меняется с value на pointer, чтобы view не копировал mutex; ключ — cache id, который уже включает цель).
- `Fetch.servedEntry` закрывает гонку sidecar: читатель, присоединившийся к чужому `Populate`, может увидеть запись до того, как владелец прописал SHA-256. В этом случае identity дочитывается через `identity.ResolveRemote` и `MarkValidated`, чтобы GET не отдал пустой checksum.
- Один пользователь не получает plaintext другого; пересечение префиксов запрещено, а user-id в namespace — вторая линия защиты.

---

## 11. Multipart

Сессия хранит:

- `uploadID`, `AccessKeyID`, `UserID`;
- `ClientKey` (ключ клиента без префикса), `Prefix`, `ProfileFingerprint` и `TargetFingerprint` на момент `CreateMultipartUpload`;
- `BackendKey`.

Проверки:

- `CreateMultipartUpload` берёт `scope.targetFingerprint()` без построения store: снимок должен пережить смену цели, а не зависеть от доступности её бэкенда.
- `UploadPart` и `CompleteMultipartUpload` используют `GetForWrite(uploadID, accessKeyID, clientKey, backendKey, userID, prefix, profileFP, targetFP)`.
  - Любое несовпадение (включая смену префикса/профиля/цели или ротацию `secret_key` цели в БД) → `404 NoSuchUpload`, запись в лог с причиной. Смена только секрета цели тоже меняет `TargetFingerprint`, поэтому старый upload отклоняется: store будет собран с новыми кредами.
- `AbortMultipartUpload` и `ListParts` используют `GetForOwner(uploadID, accessKeyID, clientKey)` и не зависят от текущего профиля/префикса/backend-ключа: прервать старую загрузку можно после смены настроек. `uploadID` — bearer-токен, привязанный к access key и клиентскому ключу; для abort/list parts этого достаточно, потому что объектные данные не читаются и не пишутся.
- `Complete` собирает части и пишет объект через `scope.archive` с `ExplicitKey = session.ClientKey`: `scope.archive` уже несёт комбинированный `(target.prefix | s3.prefix)/user.prefix` и store текущей цели, поэтому клиентский ключ не префиксуется второй раз. Профиль, ключи и цель текущего запроса уже сверены с сессией.
- Инвалидация кэша — по `scope` (`cacheBucket`/`cacheFP`).
- Части и собранный файл по-прежнему plaintext на диске шлюза; права/свипер не меняются.

---

## 12. Ошибки

| Ситуация | Код | HTTP | Результат метрики |
|---|---|---|---|
| Неизвестный `access_key_id` | `InvalidAccessKeyId` | 403 | `invalid_key` |
| Пользователь выключен | `AccessDenied` | 403 | `denied` |
| Ключ вне префикса / traversal | `AccessDenied` | 403 | `denied` |
| Неверный bucket | `AccessDenied` | 403 | `denied` |
| Неверная подпись | `SignatureDoesNotMatch` | 403 | `bad_signature` |
| БД недоступна / таймаут | `ServiceUnavailable` (новый) | 503 | `unavailable` |
| Ошибка расшифровки секрета / профиля | `InternalError` | 500 | `error` |
| Невалидная/нечитаемая цель в строке БД | `InternalError` | 500 | `error` |
| Не удалось собрать store цели | `InternalError` | 500 | `error` |
| Ошибка целевого S3 (сеть, 403 бэкенда) | `InternalError` | 500 | `error` |
| Нет профиля для `enc` объекта (GET) | `InternalError` | 500 | `error` |
| Невалидный `continuation-token` | `InvalidRequest` | 400 | `error` |
| Смена профиля/префикса/цели в multipart | `NoSuchUpload` | 404 | `not_found` |

Ошибка целевого S3 не транслируется в `403`: клиент не должен принимать отказ чужих кред за неверную подпись своего запроса. В лог идут `op`, `user_id`, `target_ns` (namespace, не fingerprint), `endpoint`, `bucket`, `err`; секреты и `Authorization` цели — никогда. Классификация «цель недоступна» → `503` в v1.2 не вводится: `port.ObjectStore` не различает сетевой отказ и отказ доступа. Это возможное расширение после появления `ErrStoreUnavailable`.

`mapAuthError` дополняется:

```go
case errors.Is(err, port.ErrAuthUnavailable):
    return s3err.ServiceUnavailable, "unavailable"
case errors.Is(err, port.ErrAuthInternal):
    return s3err.InternalError, "internal"
case errors.Is(err, port.ErrAccessDenied):
    return s3err.AccessDenied, "denied"
```

`writeAuthError` логирует `access_key_id`, `op`, `err`; секрет, ciphertext, DSN и ключевой материал не логируются.

---

## 13. CLI

Команды под `s3vault user`, `s3vault target`, `s3vault profile`:

| Команда | Назначение |
|---|---|
| `s3vault target add --name NAME --profile FILE\|-` | Создать общую цель. Полный профиль: `bucket`, `access_key`, `secret_key` обязательны; `sse_kms`/`storage_class` опциональны. |
| `s3vault target list [--output text\|json]` | имя, расположение, prefix, SSE/класс, число пользователей; секреты не показываются. |
| `s3vault target update --name NAME --profile FILE\|- [--new-name NAME] --force` | Полная замена; `--force` обязателен: меняет цель у всех привязанных. |
| `s3vault target remove --name NAME` | Удалить только несвязанную цель; иначе ошибка `ErrTargetInUse`. |
| `s3vault profile add --name NAME --file FILE\|-` | Создать общий профиль шифрования; `mode` обязателен. |
| `s3vault profile list [--output text\|json]` | имя, mode, число пользователей. |
| `s3vault profile update --name NAME --file FILE\|- [--new-name NAME] --force` | Полная замена для всех привязанных. |
| `s3vault profile remove --name NAME` | Удалить только несвязанный профиль. |
| `s3vault user add --name NAME --prefix PREFIX [--access-key ID] [--encryption-profile NAME] [--s3-target NAME]` | Создать пользователя; без флагов — глобальный профиль/глобальный S3. |
| `s3vault user list [--output text\|json]` | id, name, access_key_id, prefix, profile, target, s3, mode, enabled, created_at. |
| `s3vault user update --access-key ID [--prefix PREFIX] [--encryption-profile NAME\|--clear-encryption] [--s3-target NAME\|--clear-s3-target] [--force]` | Сменить ссылки/префикс. `--force` обязателен. |
| `s3vault user rotate --access-key ID` | Сгенерировать новый secret, напечатать один раз. Access key не меняется. |
| `s3vault user disable/enable --access-key ID` | `enabled=false/true`. |

Правила:

- `user add` генерирует `access_key_id` (`S3V` + 16 случайных букв/цифр), если `--access-key` не задан; проверяет уникальность. Явно заданный `access_key_id` — 16..128 байт, без пробелов и управляющих символов.
- Секрет генерируется всегда и печатается в stdout один раз. Аргумента для секрета нет.
- `target add/update` валидирует полный профиль и запечатывает секреты под `target_uid`; `profile add/update` валидирует профиль шифрования. Ошибка разбора файла — до открытия БД.
- `target update`/`profile update` — полная замена без частичного обновления; `--force` обязателен, потому что меняются все привязанные пользователи. Печатается число затронутых.
- `target remove`/`profile remove` отказывают, пока сущность назначена пользователям; сначала `user update --clear-s3-target`/`--clear-encryption`.
- Файл `--profile` содержит секрет цели: права `0600` — ответственность оператора; `-` читает stdin, argv и логи секрет не видят.
- `target list` в text показывает `aws/<bucket>` или `endpoint/<bucket>`; JSON — объект с `uid`, `name`, `endpoint`, `region`, `bucket`, `prefix`, `path_style`, `sse_kms`, `storage_class`, `users`, но без `access_key` и секретов.
- `user list` в text показывает `profile`/`target` и расположение; JSON — `encryption_profile` (`uid`, `name`, `mode`) и `s3_target` (как выше) или `null`.
- Все команды открывают БД, применяют миграции и используют те же `server.auth.dsn`/`S3VAULT_SERVER_AUTH_MASTER_KEY`.
- `user rotate`/`disable`/`enable` не требуют S3-кредов и `backend.type`; они работают с `server.auth.dsn`.
- Успешные операции пишут в stderr обычный лог; stdout — только результат (access key и одноразовый секрет для `add`/`rotate`; имя/uid для `target`/`profile`).

---

## 14. Тесты

### 14.1 Unit (без Postgres)

- `internal/keying/prefix_test.go`: `ValidateRelative`, `NormalizePrefix`, `NormalizeOptionalPrefix`, `PrefixesOverlap`, `JoinPrefix`; traversal (`..`, `%2e%2e`, `\`, ведущий `/`).
- `internal/adapter/s3auth/secretbox/secretbox_test.go`: roundtrip, неверный AAD, повреждённый tag, неверная длина ключа, генерация секрета/ключа.
- `internal/adapter/encrypt/profile_test.go`: разбор JSON, unknown fields, default values, native/command валидация, `Fingerprint`, выбор fallback по `enc`, `none`/legacy-классификация по magic.
- `internal/s3api/scope_test.go`: прозрачное отображение ключей, `List` prefix/start-after/continuation-token, срез префикса, `cacheBucket` с user id и целью, `storeFor` для nil/цели, `targetFingerprint`, отказ при выходе за префикс.
- `internal/s3api/session/registry_policy_test.go`: `GetForWrite` при смене profile/prefix/цели (`TargetFingerprint`); `GetForOwner` (access key + client key) для abort/list parts после смены настроек.
- `internal/s3api/auth_test.go`: маппинг `ErrAuthUnavailable` → 503, `ErrAuthInternal` → 500, `ErrAccessDenied` → 403.
- `internal/config/auth_test.go`: `backend=postgres` требует DSN, запрещает static-ключи и `s3_bucket_as_prefix`; env-ключи; `target_pool_*`; `S3APIEnabled`.
- `internal/service/fetch_profile_test.go`: выбор primary/fallback, `none` universal, legacy magic.
- `internal/httpserver/ready_test.go`: `/ready` с ошибкой `ReadyCheck` → 503.
- `internal/cli/user_test.go`: чтение профиля из файла/stdin, `profileMode`, `readS3Profile`, `s3TargetLabel`.
- `internal/adapter/s3target/profile_test.go`: строгий разбор, дефолты (region, path_style), нормализация endpoint/prefix, отказ на пустых кредах/неизвестных полях, `sse_kms`, произвольные `storage_class` (например `ICE`/`COLD`), `Namespace`/`Fingerprint` (секрет, SSE и класс меняют fingerprint, но не namespace; смена `access_key` меняет и namespace).
- `internal/adapter/s3target/pool_test.go`: переиспользование по fingerprint, пересборка при смене секрета/SSE/класса, LRU/idle, `singleflight`, отсутствие `Close` при вытеснении.

### 14.2 Integration (Postgres, `//go:build integration`)

- `internal/adapter/s3auth/postgres/postgres_integration_test.go`:
  - миграция идемпотентна; финальная схема создаётся без legacy-колонок;
  - `Lookup`: успех, неизвестный ключ, disabled, неверный мастер-ключ;
  - секрет в БД не равен plaintext; ciphertext не расшифровывается с чужим AAD;
  - `user add/list/update/rotate/disable/enable`; отказ при пересечении префиксов; неизвестный профиль/цель → `Err*NotFound`;
  - `target add/list/update/remove`, `profile add/list/update/remove`; `remove` при наличии ссылок → `Err*InUse`; переименование цели не ломает AAD; два пользователя на одной цели — одна строка цели, `users=2`;
  - стартовая валидация: битый профиль/секрет/цель/пересечение → `Open` падает; тот же `Open` с `SkipValidation: true` открывается, чтобы CLI мог исправить строку;
  - прямой SQL-insert с пересекающимся префиксом или битой целью → старт падает;
  - ciphertext, перенесённый в другую строку цели, не расшифровывается;
  - `secret_key`/`session_token` цели не лежат в `config jsonb` и не возвращаются `ListTargets`/`ListUsers`.
- `internal/s3api/facade_postgres_integration_test.go`:
  - два пользователя с разными префиксами и одинаковым клиентским ключом пишут в разные backend-ключи;
  - `List` показывает только собственный ключ;
  - `Delete` не трогает соседний префикс;
  - `disable` → `403`;
  - два пользователя с одним общим `native`-профилем (`key_file`) пишут `S3VCTR01` и читают обратно;
  - два пользователя с одной общей целью пишут в отдельный `memStore` через подменённый `TargetResolver`; `List`/`Delete`/`Get` идут в него, а не в глобальный;
  - `target update` меняет цель у всех привязанных: старый ключ невидим, новый Put уходит в новый store;
  - смена `TargetFingerprint` в середине multipart → `Complete` отвечает `NoSuchUpload`, `Abort` работает;
  - кэш с целью и без неё не пересекается по id.

Интеграционные тесты используют `S3VAULT_TEST_POSTGRES_DSN` и `t.Skip`, если он не задан. Unit-тесты не требуют Postgres. Пакеты `internal/adapter/s3auth/postgres` и `internal/s3api` делят одну тестовую БД и очищают таблицу, поэтому в CI они запускаются с `-p 1`.

### 14.3 E2E (Postgres-стенд)

`compose.e2e.yaml` получает сервис `postgres:18`; `scripts/e2e.sh postgres` — одна фаза:

1. `user add` для двух пользователей; отказ при пересекающемся префиксе.
2. `Put/Get/List` под каждым пользователем; проверка, что backend-ключи разные, а `List` не показывает префикс.
3. `disable` → `403`, `enable` → снова работает, `rotate` → новый секрет работает.
4. При compose-стенде: остановка PostgreSQL → `/ready` 503 и S3 503 (не 403); после рестарта — восстановление. В режиме `S3VAULT_E2E_NO_COMPOSE=1` этот шаг пропускается, потому что внешний сервис не перезапускается скриптом.

Отдельная фаза `scripts/e2e.sh postgres_target` (нужны и MinIO, и Postgres) проверяет конечный S3 на живом стенде:

1. Создать второй bucket (`s3vault-alt`), `target add` и двух пользователей с `--s3-target`, указывающим на него.
2. Put/Get/List под этими пользователями; raw-проверка, что объекты лежат в alt-bucket под `target.prefix/user.prefix/`, и что в основном bucket их нет.
3. Пользователь без цели пишет в основной bucket; `List` каждого видит только своё.
4. `target update` на третий prefix/bucket: старый ключ → `404`, новый Put уходит в новое место; `user update --clear-s3-target` возвращает в глобальный S3.
5. Цель с неверными кредами → `5xx` (не `403`) и запись в лог без секретов.
6. Multipart: создать upload, загрузить часть, изменить цель (через `target update`), `Complete` → `404 NoSuchUpload`, `Abort` работает.

Native-профиль и multipart/cache-политика проверяются integration/unit-тестами, а не отдельными e2e-фазами. CI: `integration.yml` и `e2e.yml` получают Postgres service/контейнер; для `postgres_target` скрипт создаёт второй bucket; `go test -race ./...` остаётся без Postgres для unit.

---

## 15. Документация

Обновлено вместе с реализацией:

- `architecture.md` §«S3 API gateway»: два backend'а auth, схема БД, per-request scope, прозрачный префикс, fallback, cache namespace, multipart binding, 503 при отказе БД; статус-таблица и раздел зависимостей (`pgx/v5`).
- `README.md`: раздел «Пользователи gateway в PostgreSQL» — env, `user add`, формат JSON профиля, примеры клиента, ограничения (нет перешифровки/ротации мастер-ключа, fallback только по алгоритму).
- `s3vault.example.yaml`: закомментированная секция `server.auth`.
- `.env.example`: `S3VAULT_SERVER_AUTH_BACKEND`, `S3VAULT_SERVER_AUTH_DSN`, `S3VAULT_SERVER_AUTH_MASTER_KEY`.
- `compose.e2e.yaml`, `scripts/e2e.sh`, CI workflows.

При реализации §19 добавить:

- `README.md`: подраздел «Конечный S3 пользователя» — зачем, `target add/update`, полная замена, `target.prefix/user.prefix`, отсутствие миграции объектов, `--clear-s3-target`, ограничения.
- `architecture.md` §«S3 API gateway»: per-request `storeFor`, пул целей, `|s3:<ns>` в кэше, `TargetFingerprint` в multipart; статус-таблица.
- `spec/agents/hard-rules.md`: уточнить формулировку «один `ObjectStore` из `newObjectStore`» — глобальный store остаётся один, но в `postgres`-режиме появляется ограниченный пул store'ов для целей; store по-прежнему не создаётся на каждый запрос.
- `s3vault.example.yaml`: `server.auth.target_pool_max`/`target_pool_idle`; пример `s3_target` не в YAML (он в БД).
- `.env.example`: `S3VAULT_SERVER_AUTH_TARGET_POOL_MAX`, `S3VAULT_SERVER_AUTH_TARGET_POOL_IDLE`.
- `compose.e2e.yaml`, `scripts/e2e.sh`: второй bucket, фаза `postgres_target`, второй Postgres не нужен.

---

## 16. Явно не входит

- Перешифровка/миграция существующих объектов под новые профили.
- Ротация мастер-ключа и online-перешифровка `secret_key` в БД.
- Несколько access key, префиксов, профилей шифрования или конечных S3 на пользователя.
- Выбор цели клиентом (по bucket/заголовку).
- Миграция/копирование/перешифровка объектов между целями; `CopyObject` между целями.
- Per-target TLS (свой CA/клиентский сертификат), assume-role, IMDS, прокси, лимиты и квоты.
- Автоматическое обновление временных `session_token` (STS): токен хранится как статический и по истечении обновляется оператором вручную.
- Проверка доступности целей в `/ready` и per-target health-check.
- Группы, роли, ACL по операциям (read-only/read-write), wildcard-политики.
- Квоты, rate limit, audit-таблица, per-user метрики.
- Кэш аутентификации и инвалидация между репликами.
- TLS до PostgreSQL (задаётся через `sslmode`, но не является требованием стенда).
- `CopyObject`, `CreateBucket`, virtual-host style.
- UI и отдельный admin-сервис.
- Аутентификация CLI `archive`/`download` через БД: они ходят под S3-кредами пользователя.

---

## 17. Ограничения и риски

- PostgreSQL — корень доверия: компрометация БД позволяет добавить пользователя и читать/писать его объекты.
- Мастер-ключ в env: компрометация процесса раскрывает все `secret_key`.
- Нет кэша auth: при падении БД шлюз отвечает 503 и не обслуживает данные (fail-closed). При 10 RPS это приемлемо.
- `sslmode=disable` допустим только в приватной сети стенда; для production нужен TLS.
- Смена префикса оставляет объекты в старом месте и делает их недоступными пользователю.
- Смена профиля без перешифровки может сделать старые объекты нечитаемыми; fallback помогает только при смене алгоритма.
- Одинаковый алгоритм с другими ключами fallback-ом не покрывается.
- Прямые SQL-правки таблицы не поддерживаются: инварианты (канонический префикс, непересечение) проверяют CLI и старт.
- Отключение пользователя не прерывает уже аутентифицированный in-flight запрос; следующий запрос получает 403.
- Стартовая валидация читает всех пользователей и все ключи; при большом количестве пользователей это станет заметным, но для стенда приемлемо.
- Цель — это доверенный ввод оператора. Компрометация БД позволяет перенаправить пользователя на чужой endpoint и получить его plaintext (эквивалент добавления пользователя). Креды цели должны иметь минимальные права на свой bucket.
- Изоляция между пользователями с общей целью держится на прозрачном префиксе шлюза, а не на IAM цели. Если нужна жёсткая изоляция, каждая цель должна иметь свои креды/политику на bucket.
- Пул ограничен `target_pool_max`; при большем числе активных целей LRU будет пересоздавать store'ы. Это не ошибка, но лишние аллокации и TLS-handshake; размер пула подбирается по числу одновременно активных целей.
- Смена цели не переносит объекты. Delete после смены удаляет ключ в новой цели, а не в старой. `--force` — единственная защита; перешифровки/миграции нет.
- Цель с `http://` отключает TLS до неё; допустимо только в приватной сети. Свой CA в v1.2 не поддерживается.
- `/ready` не видит отказ цели; мониторинг должен проверять каждый целевой endpoint отдельно.
- Кэш для удалённой/сменённой цели остаётся на диске до TTL/LRU; он недоступен по id, но это по-прежнему plaintext. `cache clear` — единственное немедленное удаление.

---

## 18. Ссылки

- `architecture.md` §«S3 API gateway (SigV4 plaintext facade)», §«Object format», §«Layer ownership», §«Cache».
- `internal/port/s3identity.go` — `Principal`, `UserPolicy`, `S3Target`, `S3Identity`, `S3Op`, `ErrAuthUnavailable`, `ErrAuthInternal`.
- `internal/adapter/s3auth/postgres/postgres.go` — `Open`, `migrate`, `validateAll`, `sealSecret`/`openSecret`.
- `internal/adapter/s3auth/postgres/identity.go` — `Lookup`, `Allow`.
- `internal/adapter/s3auth/postgres/admin.go` — `ListUsers`, `AddUser`, `UpdateUser`, `RotateSecret`, `SetEnabled`.
- `internal/adapter/s3auth/secretbox/secretbox.go` — `ParseKey`, `Seal`, `Open`, `GenerateSecret`.
- `internal/s3api/auth.go` — `AuthLayer`, `credProvider`, `mapAuthError`.
- `internal/s3api/handler.go` — `serveHTTP`, `clientPath`, диспетчеризация операций.
- `internal/s3api/scope.go` — `newScope`, `profileFor`, `storeFor`, `targetFingerprint`, `archiveFor`, `fetchFor`, `listPrefix`, `stripKey`, `encodeToken`, `invalidateCache`.
- `internal/s3api/session/registry.go` — `CreateForUser`, `GetForWrite`, `GetForOwner`.
- `internal/service/archive.go` — `WithFraming`, `WithProfile`, `WithStore`, `writesRaw`, `UploadFile`.
- `internal/service/fetch.go` — `WithCache`, `WithProfile`, `WithStore`, `Open`, `Materialize`, `unwrapForDecrypt`, `servedEntry`.
- `internal/service/fetch_profile.go` — `encryptorFor`, `legacyEncryptor`, `decryptStream`.
- `internal/adapter/encrypt/profile.go`, `names.go` — `Resolver`, `Profile`, `ResolveRaw`, `Name`, `NameNone`/`NameNative`/`NameCommand`.
- `internal/adapter/encrypt/detect.go` — `DecryptAuto`, `decryptLegacy`, `LegacyKind`.
- `internal/keying/prefix.go` — `ValidateRelative`, `NormalizePrefix`, `NormalizeOptionalPrefix`, `PrefixesOverlap`, `JoinPrefix`.
- `internal/cli/user.go` — `newUserCmd` и подкоманды, `readS3Profile`.
- `internal/adapter/s3target/` — `Decode`, `DecodeStored`, `StoredJSON`, `Validate`, `Namespace`, `Fingerprint`, `Pool`.
- `spec/agents/hard-rules.md` — идентичность, слои, секреты, конфиг.

---

## 19. Профиль конечного S3 у пользователя

**Статус:** реализовано (v1.3). При `s3_target_uid IS NULL` поведение §1–18 не меняется.

### 19.1 Задача и термины

Сейчас у шлюза один конечный S3: глобальный `s3.*` (endpoint, region, bucket, prefix, path-style, креды) или `backend.local.dir`. Нужно разрешить отдельному пользователю БД работать с другим конечным S3, не меняя клиентский интерфейс: клиент по-прежнему видит один виртуальный bucket и относительные ключи без префикса.

Термины:

- **цель** (`s3vault_targets`) — сохранённый в БД общий профиль конечного S3; пользователь ссылается на него через `s3_target_uid`;
- **глобальный S3** — текущий `s3.*`, используемый при `s3_target_uid IS NULL`;
- **namespace цели** — SHA-256 несекретных полей (включая `access_key`); используется в namespace кэша, ephemeral-ключей и логах;
- **fingerprint цели** — SHA-256 всех полей, включая хэши секретов; используется как ключ пула store'ов и в снимке multipart-сессии. В логи и ответы не попадает.

### 19.2 Семантика: полная замена

`NULL` — глобальный S3, поведение §1–18 без изменений. Непустая цель — **полная замена**, без слияния полей:

| Что | Источник при непустой цели |
|---|---|
| `endpoint`, `region`, `bucket`, `path_style` | цель |
| `access_key`, `secret_key`, `session_token` | цель; глобальные креды не используются |
| `prefix` | цель; глобальный `s3.prefix` не применяется |
| `s3.multipart_part_size` | глобальный: это политика writer'а, а не свойство хранилища |
| `server.s3_bucket` | глобальный: имя виртуального bucket'а для клиента |
| `server.s3_bucket_as_prefix` | по-прежнему запрещён в `postgres` |

Почему не частичное слияние: отсутствующий `secret_key` молча взял бы глобальные креды и отправил бы их на чужой endpoint; отсутствующий `bucket` — писал бы в глобальный. Полная замена делает такую ошибку невозможной: профиль либо задан целиком, либо не задан.

Отображение ключей:

```
backend_key = target.prefix / user.prefix / client_key
```

При `NULL`: `s3.prefix / user.prefix / client_key`, как сейчас. `target.prefix` не виден клиенту; `ListObjectsV2` срезает `target.prefix/user.prefix/` так же, как сейчас срезает `s3.prefix/user.prefix/`. Если нужен общий deployment-wide namespace, его включают в `target.prefix`; глобальный `s3.prefix` к цели не подмешивается.

Пример: цель с `prefix=vault`, пользователь с `prefix=tenant-a`, клиентский ключ `report.pdf` → `vault/tenant-a/report.pdf` в `target.bucket`. Клиент видит `report.pdf`.

`backend.type=local` не запрещает цель: глобальный store остаётся локальным, а пользователь с целью ходит в S3. Цель по определению всегда S3. Если гомогенность важнее, оператор просто не задаёт цели. `/ready` при этом проверяет только локальный store.

Глобальный store строится и проверяется всегда, даже если цели есть у всех пользователей: он обслуживает пользователей без цели и `/ready`. Нельзя «выключить» глобальный S3, оставив только цели.

Смена цели:

- `user update --s3-target`/`--clear-s3-target` и `target update` требуют `--force`;
- старые объекты остаются в старом хранилище и через шлюз больше не адресуются; миграции нет;
- последующий `Delete`/`Put` с тем же клиентским ключом действует только на новую цель; объект в старой цели не трогается;
- старый `continuation-token` после смены цели/префикса не переносится: листинг нужно начинать заново;
- вернуть доступ к старым объектам можно, только вернув прежнюю цель (endpoint/bucket/prefix/креды) или обратившись к хранилищу напрямую.

Fallback на глобальный S3 при промахе в цели нет: иначе после смены цели старые и новые объекты смешивались бы, а `List`/кэш стали бы неоднозначными. Для миграции объекты копируются вне шлюза (в scope не входит).

Цель не добавляет и не убирает слой шифрования: шлюз по-прежнему обрамляет объект ровно один раз, а `encryption` пользователя выбирается независимо от цели.

### 19.3 Схема БД

Цель — строка `s3vault_targets`, пользователь ссылается на неё через `s3_target_uid` (nullable, `ON DELETE RESTRICT`). Полная итоговая схема — в §3.1; отдельных legacy-колонок `s3_target`/`s3_secret_*`/`s3_session_*` в `s3vault_users` нет.

Свойства:

- одна цель на пользователя (одна ссылка), но одна и та же цель — у многих пользователей;
- `config jsonb` содержит только несекретные поля, включая `sse_kms` и `storage_class`; `secret_key`/`session_token` в `jsonb` запрещены констрейнтом;
- `uid` неизменяем и входит в AAD; `name` уникально и изменяемо;
- `target remove`/`profile remove` отказывают, пока есть ссылки;

### 19.4 JSON профиля и валидация

Входной файл `s3vault target add/update --profile`:

```json
{
  "endpoint": "https://s3.example.com",
  "region": "us-east-1",
  "bucket": "alice-archive",
  "prefix": "vault",
  "path_style": true,
  "access_key": "AKIA...",
  "secret_key": "...",
  "session_token": "",
  "storage_class": "STANDARD_IA",
  "sse_kms": {
    "key_id": "arn:aws:kms:us-east-1:123456789012:key/abc",
    "context": {"tenant": "alice"},
    "bucket_key": true
  }
}
```

Правила:

| Поле | Обяз. | Правило |
|---|---|---|
| `endpoint` | нет | Пусто = endpoint AWS. Иначе абсолютный `http`/`https` URL с непустым host; без userinfo, query и fragment; хвостовой `/` срезается; scheme/host нормализуются в нижний регистр. |
| `region` | нет | Пусто → `us-east-1` (как default `s3.region`). 1..64 байта, без пробелов и управляющих символов. |
| `bucket` | да | 1..255 байт; без `/`, `\`, NUL и управляющих символов; без пробелов по краям. |
| `prefix` | нет | Пусто допустимо. Иначе — `keying.NormalizeOptionalPrefix`: срезать пробелы и `/`, сегменты непустые, без `.`/`..`, `\`, NUL. |
| `access_key` | да | 1..128 байт, без NUL и управляющих символов. |
| `secret_key` | да | 1..512 байт, без NUL; не тримится. В `jsonb` не попадает. |
| `session_token` | нет | 0..4096 байт, без NUL. В `jsonb` не попадает. |
| `path_style` | нет | По умолчанию `false`. |
| `storage_class` | нет | Пусто = не отправлять `x-amz-storage-class`. Иначе произвольная строка 1..64 байт без пробелов и управляющих символов; передаётся **как есть**, без ограничения списком AWS. Например `ICE`, `COLD`, `COLDLINE`. Совместимость значения с конечным S3 — ответственность оператора; классы AWS `GLACIER`/`DEEP_ARCHIVE` требуют restore перед GET. |
| `sse_kms` | нет | Отсутствие = SSE не используется и SSE-заголовки не отправляются. Присутствие (в том числе `{}`) = `ServerSideEncryption: aws:kms` на Put и CreateMultipartUpload. |
| `sse_kms.key_id` | нет | 0..2048 байт, без пробелов/управляющих символов; пусто = ключ KMS по умолчанию для bucket. |
| `sse_kms.context` | нет | До 64 пар; ключ 1..256 байт, значение 0..1024 байт, суммарно до 8192 байт; без NUL. Сериализуется в base64(JSON) как `SSEKMSEncryptionContext`. |
| `sse_kms.bucket_key` | нет | По умолчанию `false`; при `true` шлюз отправляет `BucketKeyEnabled`. |

- Разбор строгий: `DisallowUnknownFields` (включая вложенный `sse_kms`), хвостовые JSON-значения отвергаются; размер файла/stdin — не более 64 KiB.
- Неизвестное поле (включая `multipart_part_size` и `type`) — ошибка, а не игнор: конфиг цели должен быть однозначным.
- Пустые `access_key`/`secret_key` запрещены: иначе SDK ушёл бы в env/IMDS процесса, и цель молча работала бы под чужими кредами.
- Пустой `endpoint` означает не «никуда», а цепочку AWS SDK: на него всё ещё влияют process-wide `AWS_ENDPOINT_URL`, `AWS_CA_BUNDLE` и прокси. Для полной изоляции цели задавайте `endpoint` явно; per-target CA/прокси в v1.2 не поддерживаются.
- `s3target.Decode` принимает CLI-профиль с секретами; для `config jsonb` используется отдельный разбор несекретной части, иначе отсутствие `secret_key` в БД считалось бы ошибкой.
- Нормализация выполняется один раз в `s3target.Decode` при `target add`/`target update`; `Lookup` повторно валидирует, но не переписывает строку.
- `s3store.NewWithOptions` получает `config.S3Config{Endpoint, Region, Bucket, AccessKey, SecretKey, SessionTok, PathStyle, MultipartPartSize: cfg.S3.MultipartPartSize}` и `s3store.Options{ServerSideEncryption, SSEKMSKeyID, SSEKMSContext, BucketKeyEnabled, StorageClass}`. `Prefix` в store не передаётся: его применяет `keying.Mapper`.
- Bucket не создаётся: как и сейчас, он должен существовать. Ошибка доступа к bucket — ошибка целевого S3, а не auth.

### 19.5 Секреты цели

- Тот же мастер-ключ `S3VAULT_SERVER_AUTH_MASTER_KEY`, AES-256-GCM, случайный 12-байтовый nonce на запись.
- `secret_nonce`/`secret_ciphertext` — `secret_key`, `session_nonce`/`session_ciphertext` — `session_token` в строке `s3vault_targets`; AAD: `s3.secret_key:<target_uid>` и `s3.session_token:<target_uid>`.
- Домены AAD разделены: фронтенд-секрет использует `<access_key_id>`, цель — префиксы `s3.secret_key:`/`s3.session_token:` + `target_uid`. Перестановка ciphertext между строкой цели, колонкой или полем не расшифруется.
- `target_uid` неизменяем. Переименование цели не требует перешифровки; прямая SQL-правка `uid` делает секреты нечитаемыми, старт падает.
- `secret_key`/`session_token` цели не принимаются argv, не печатаются, не логируются и не возвращаются `target list`/`user list`.
- Ротации мастер-ключа нет; смена ключа делает нечитаемыми и фронтенд-секреты, и секреты целей.
- Отдельной команды ротации секрета цели нет: `user rotate` меняет только фронтенд-секрет. Секрет цели меняется полной заменой через `target update --profile ... --force`.

### 19.6 Lookup и Principal

`Lookup` делает `LEFT JOIN` на реестры, расшифровывает секреты цели и заполняет `UserPolicy.Target` (§7.1). Правила:

- `s3_target_uid IS NULL` → `Target == nil`, глобальный S3;
- `encryption_profile_uid IS NULL` → `Encryption == nil`, глобальный профиль;
- цель есть → разобрать `config`, расшифровать `secret_*` (и `session_*`, если задан), собрать `port.S3Target`, прогнать `s3target.Validate`;
- ошибка разбора/расшифровки/валидации → `port.ErrAuthInternal` → `500`, лог с `access_key_id`/target name и причиной, без секретов;
- `Allow` не меняется: цель не участвует в авторизации, её задаёт оператор, а не клиент.
- `validateAll` проверяет реестры целиком (включая неиспользуемые строки) и пользователей; сетевых запросов нет.
- `ListTargets`/`ListUsers` читают только несекретные поля и возвращают typed-структуры: даже прямой SQL с лишними полями не утечёт в `--output json`.

### 19.7 Пул store'ов

Новый пакет `internal/adapter/s3target`:

```go
func Decode(raw []byte) (port.S3Target, error)
func Validate(t port.S3Target) error
func Namespace(t port.S3Target) string   // поля места: endpoint/region/bucket/prefix/path_style/access_key
func Fingerprint(t port.S3Target) string // все поля, включая хэши секретов, sse_kms и storage_class

type TargetResolver interface {
    Store(ctx context.Context, t port.S3Target) (port.ObjectStore, error)
}
```

Каноническое кодирование для `Namespace`/`Fingerprint` версионировано (`s3target:v1`) и использует length-prefixed поля, чтобы значения с `/` и пустые строки не давали коллизий. `Fingerprint` хэширует `secret_key`/`session_token`, а не хранит их в открытом виде, и включает `sse_kms`/`storage_class`: смена любого из них должна пересобрать store в пуле.

`Pool` реализует `TargetResolver`:

- ключ — `Fingerprint(t)`; значение — `ObjectStore` + `lastUsed`;
- `singleflight` на ключ: параллельные первые запросы строят один store;
- LRU + `server.auth.target_pool_max`; запись старше `server.auth.target_pool_idle` вытесняется фоновым sweeper'ом (раз в минуту) и лениво при `Store`;
- builder — `s3store.NewWithOptions` с параметрами §19.4, включая `sse_kms`/`storage_class`; построение не делает сетевых запросов, первый S3-вызов может упасть уже в операции;
- вытеснение **не** вызывает `Close`: `port.ObjectStore` не имеет жизненного цикла, а store может ещё использоваться in-flight запросом. Ресурсы освобождаются при завершении процесса; будущие адаптеры не должны требовать `Close`;
- `Pool.Close()` останавливает sweeper (вызывается при остановке `server` и в тестах), store'ы не закрывает;
- пул — на процесс; реплики не координируются;
- если `target_pool_max` меньше числа активных целей, LRU будет пересоздавать store'ы; это деградация производительности, а не ошибка. Размер пула подбирается по числу одновременно активных целей.

Глобальный store из `newObjectStore` в пул не входит и остаётся default для пользователей без цели и для `/ready`.

Пул не является кэшем аутентификации: `Lookup` по-прежнему читает БД на каждый запрос и отдаёт снимок цели; пул лишь переиспользует уже построенный store по fingerprint. Поэтому disable/rotate/смена цели видны со следующего запроса, как и в §7.1.

### 19.8 Per-request scope

Дополнения к §7.3:

- `scope.target` — снимок `principal.User.Target`;
- `basePrefix` — `target.Prefix` или глобальный `api.keys.Prefix`;
- `storeFor(ctx)` — `api.store` при `target == nil`, иначе `api.targets.Store(ctx, *target)`;
- `targetFingerprint()` — `""` или `s3target.Fingerprint(*target)`, без построения store;
- `archiveFor`/`fetchFor` добавляют `WithStore` к view (у `Fetch` — с namespace для ephemeral-ключей);
- `List`/`Delete` берут store из scope, а не из `api.store`;
- `CreateMultipartUpload`/`UploadPart` не строят store, только берут fingerprint;
- `HeadBucket`/`ListBuckets`/`Abort`/`ListParts` не разрешают ни store, ни профиль.

### 19.9 Кэш и ephemeral

- Namespace: `CacheNamespace() + "|user:<id>"`, при цели — `+ "|s3:" + Namespace(target)`. Для пользователей без цели строка не меняется, старые cache id остаются валидными.
- `Namespace` цели покрывает `endpoint`, `region`, `bucket`, `prefix`, `path_style`, `access_key`; `secret_key`/`session_token` и write-side `sse_kms`/`storage_class` не входят, поэтому ротация секрета, включение SSE или смена класса хранения не инвалидируют кэш (данные лежат там же).
- `Fingerprint` (с секретами и write-side параметрами) для кэша не используется; он нужен пулу и multipart.
- `Fetch.WithStore(store, namespace)` ставит namespace в ключ `ephemeralSet`: `namespace + "\x00" + backend_key`. Пустой namespace сохраняет прежнее поведение.
- `reval` использует cache id, который уже включает namespace цели.
- `Put`/`Delete`/`Complete` инвалидируют запись по текущему `cacheBucket` + `cacheFP`.
- После смены/удаления цели старые записи кэша недоступны по id, но остаются на диске до TTL/LRU; `cache clear` удаляет немедленно.

### 19.10 Multipart

- Сессия хранит `TargetFingerprint` (пусто = глобальный S3) рядом с `UserID`/`ClientKey`/`Prefix`/`ProfileFingerprint`.
- `UploadPart`/`Complete` сравнивают текущий `targetFingerprint()` со снимком; несовпадение → `404 NoSuchUpload`.
- Ротация `secret_key` цели меняет `Fingerprint`, поэтому старый upload отклоняется: `Complete` собрал бы store с новыми кредами, а части — со старым снимком.
- `Abort`/`ListParts` по-прежнему проверяют только access key + client key и работают после смены цели.
- `Complete` пишет через `scope.archive` текущей цели; части и собранный файл остаются plaintext на диске шлюза, права/свипер не меняются.

### 19.11 Конфигурация

```yaml
server:
  auth:
    target_pool_max: 64
    target_pool_idle: 15m
```

| Ключ | Env | Default | Смысл |
|---|---|---|---|
| `server.auth.target_pool_max` | `S3VAULT_SERVER_AUTH_TARGET_POOL_MAX` | `64` | Максимум store'ов в пуле; `0` → default, отрицательное — ошибка. |
| `server.auth.target_pool_idle` | `S3VAULT_SERVER_AUTH_TARGET_POOL_IDLE` | `15m` | Простой до вытеснения; `0` → default, отрицательное — ошибка. |

Других глобальных ключей цель не добавляет: endpoint/bucket/креды живут в БД. `s3.multipart_part_size` остаётся глобальным.

### 19.12 Ошибки, старт и readiness

- Невалидная/нечитаемая цель в строке → `Open` падает на старте; в рантайме (прямая SQL-правка) — `ErrAuthInternal` → `500`.
- Не удалось собрать store цели → `500` с логом; auth при этом исправен.
- Ошибка операции целевого S3 (сеть, 403 бэкенда) → `500 InternalError`, не `403`: отказ чужих кред нельзя выдавать за неверную подпись клиента.
- Смена цели/профиля/префикса в multipart → `404 NoSuchUpload`.
- `/ready` не проверяет цели: недоступность одного бэкенда не должна выводить из ротации весь шлюз. Отказ цели виден только её пользователю и в логах.
- Классификация «цель недоступна» → `503` в v1.2 не вводится: `port.ObjectStore` не различает сеть и отказ доступа. Это возможное расширение после `ErrStoreUnavailable`.

### 19.13 CLI

- `target add/list/update/remove` — управление общими целями. `target add/update --profile FILE|-` принимает полный профиль; `update` требует `--force` и сообщает число затронутых пользователей.
- `profile add/list/update/remove` — управление общими профилями шифрования. `add/update --file FILE|-`; `update` требует `--force`.
- `user add ... [--s3-target NAME] [--encryption-profile NAME]` — ссылки при создании; без флагов — `NULL` (глобальные).
- `user update --access-key ID [--s3-target NAME|--clear-s3-target] [--encryption-profile NAME|--clear-encryption] [--force]` — меняет ссылки, а не сущности; `--force` обязателен.
- `user list`/`target list` — несекретные typed-структуры; JSON содержит `uid`/`name`/расположение/`sse_kms`/`storage_class`, но не `access_key` цели и не секреты.
- Один и тот же `target`/`profile` назначается нескольким пользователям. `target remove`/`profile remove` отказывают, пока есть ссылки.
- Файл цели содержит секрет: права `0600` — ответственность оператора; `-` читает stdin; argv и логи секрет не видят.
- `user add` не печатает секрет цели (его задал оператор); печатается только сгенерированный фронтенд-секрет.
- Ошибка разбора файла — до открытия БД.

### 19.14 Тесты

Unit:

- `s3target`: строгий разбор, дефолты, нормализация endpoint/prefix, отказ на пустых кредах/неизвестных полях, `Namespace`/`Fingerprint` (секрет меняет fingerprint, но не namespace; `sse_kms`/`storage_class` меняют fingerprint, но не namespace); разбор/валидация `sse_kms` и `storage_class`, отсутствие = не отправлять заголовки.
- `s3target.Pool`: переиспользование по fingerprint, пересборка при смене секрета, SSE или класса, LRU/idle, `singleflight`.
- `s3store`: `x-amz-server-side-encryption*` и `x-amz-storage-class` отправляются только при заданных опциях, и на одиночном PUT, и на `CreateMultipartUpload`.
- `scope`: `target.prefix/user.prefix`, `|s3:<ns>` в `cacheBucket`, `storeFor` для nil/цели, `targetFingerprint`; два пользователя с одинаковым профилем/целью получают одинаковый fingerprint и изолированные `cacheBucket`.
- `session`: `TargetFingerprint` в `GetForWrite`, `GetForOwner` не зависит от цели.
- `user`: `readS3Profile`, `s3TargetLabel`, отсутствие секретов в JSON-выводе, наличие `sse_kms`/`storage_class` в нём.

Integration (Postgres):

- Реестры: `target add/list/update/remove`, `profile add/list/update/remove`, переименование, отказ `remove` при ссылках, `users=N`, финальная схема без legacy-колонок.
- Секреты цели: не в `config jsonb`, не возвращаются `ListTargets`, не расшифровываются с чужим AAD; `user update --clear-s3-target` снимает ссылку, а не удаляет цель.
- `facade_postgres_integration_test.go`: два пользователя с одной целью пишут/читают/удаляют/листают через отдельный store; цель и глобальный S3 не пересекаются; `target update` меняет цель у обоих; смена `TargetFingerprint` в multipart → `NoSuchUpload`; два пользователя с одним профилем шифрования работают.

E2E:

- `scripts/e2e.sh postgres_target` (MinIO + Postgres): второй bucket, `target add`, два пользователя с одной целью, raw-проверка расположения, изоляция от пользователя без цели, `target update`/`--clear-s3-target`, неверные креды → `5xx`, multipart при смене цели → `404`.

### 19.15 Документация

- `README.md`: «Конечный S3 пользователя» — `target add/update`, полная замена, `target.prefix/user.prefix`, отсутствие миграции объектов, `--clear-s3-target`, ограничения.
- `architecture.md`: `storeFor`, пул целей, `|s3:<ns>` в кэше, `TargetFingerprint` в multipart, реестры.
- `spec/agents/hard-rules.md`: уточнить «один ObjectStore» — глобальный store остаётся один, но в `postgres` появляется ограниченный пул целей; store не создаётся на каждый запрос.
- `s3vault.example.yaml`, `.env.example`: `target_pool_max`/`target_pool_idle`.
- `compose.e2e.yaml`, `scripts/e2e.sh`, CI: второй bucket и фаза `postgres_target`.

### 19.16 Явно не входит

- Несколько целей на пользователя и выбор цели клиентом.
- Глобальные `sse_kms`/`storage_class` для всех пользователей: это свойства цели, а не шлюза.
- Миграция/копирование объектов между целями; `CopyObject` между ними.
- Per-target TLS (свой CA/клиентский сертификат), assume-role, IMDS, прокси, квоты.
- Автоматическое обновление временных `session_token` (STS): токен хранится как статический и по истечении обновляется оператором вручную.
- Проверка целей в `/ready` и per-target health-check.
- Шифрование `access_key` цели (это идентификатор, не секрет).

### 19.17 Риски и ограничения

См. §17 (риски цели перечислены там же): перенаправление через БД, зависимость изоляции от префикса, ограниченный пул, отсутствие миграции объектов, `http://`, невидимость отказа цели в `/ready` и plaintext-кэш сменённой цели. Дополнительно: стартовая валидация цели не проверяет её доступность, поэтому первый запрос пользователя может упасть, если bucket/креды неверны.

### 19.18 Открытые вопросы

Приняты по умолчанию; подтвердить при реализации:

1. Разрешать цель при `backend.type=local` (сейчас — да, цель всегда S3).
2. Не показывать `access_key` цели в `user list` (сейчас — только `endpoint/bucket`; JSON тоже без ключа). Если оператору нужен ключ для сверки, его можно добавить в JSON как несекретное поле.
3. Не включать цели в `/ready` (сейчас — нет; отказ цели не влияет на общую готовность).
