# Известные проблемы

Бэклог дефектов, найденных при сверке `architecture.md` с кодом и сплошным аудитом путей записи/удаления/чтения.

**Актуализировано 2026-11-13.** Решённые и снятые пункты удалены: D1–D3 (исправлены: `7125b0a`, `39c500c`, `4475601`), D12 и D15 (опровергнуты прогоном), P1-legacy и P2 (закрыты), пункт про `start-after` и префикс в List (исправлен — закрывается `TestScopeStartAfter`/`TestScopeListPrefix`) и пункт про метрику скачивания (опровергнут прогоном: `return cw.n, f.decryptStream(...)` читает `cw.n` после вызова, метрика показывает фактические байты). История карточек — в git.

**P1-итерация и D5/D8/KEK, 2026-11-13:** D4, D5, D6, D8, D13, D14 и пустой keyfile исправлены и закрыты постоянными тестами (`TestArchiveDeleteFlagsOverrideConfig`, `TestUploadDeleteFlagsOverrideConfig`, `TestDiskPopulateDiscardsWhenEntryInvalidated`, `TestDiskMarkValidatedKeepsFresherIdentity`, `TestFetchPopulateInvalidatedMidDownloadServesCurrentVersion`, `TestFetchMaterializeSWRRepopulatesOnChange`, `TestFetchDownloadRejectsTruncatedObject`, `TestFetchMaterializeRejectsTruncatedObject`, `TestArchiveUploadRejectsChangedSource`, `TestLoadKEKRejectsEmptyKeyFile`); карточки удалены, механика зафиксирована в `architecture.md` (Cache, Download, Archive reliability, encryption). Оставшиеся пункты переатестированы в тот же день: по каждому — чтение актуального кода и детерминированный прогон временным тестом с префиксом `TestZZVERIF_*` (после прогона тест удалён, продакшн-код не менялся). В каждой карточке строка **Проверка:** с командой и наблюдаемым результатом.

Статусы: `🟥` — подтверждён, открыт (потеря/порча данных); `🟠` — подтверждён механизм или его часть, есть смягчающий контур; ✅/❌ в строке **Проверка:** — подтверждён/опровергнут прогоном.

Ничего из перечисленного **не** является дефектом формата `S3VCTR01`: контейнер, послойность владения и дедуп проверены побайтово и корректны.

## Сводка

**Открыто: 4 пункта** (D7, D9–D11) + 2 наблюдения в «Прочем» + 1 подтверждённый контракт (D16).

| Пункт | Суть | Проверка |
| --- | --- | --- |
| D7 | не-unix lock — no-op, Windows в релизе | ✅ сборкой |
| D9 | containerless `Salted__` под unmanaged-читателем | ✅ прогон |
| D10 | namespace кэша не включает `s3.endpoint`/аккаунт | ✅ unit |
| D11 | `max_sessions` сносит живую multipart-сессию | ✅ прогон |

---

## Потеря / порча данных (`🟥`)

Все пункты ниже — пути, где данные могут быть удалены или записаны искажённо **без ошибки на выходе**. Порядок — по достижимости из штатного конфига.

### D7 — кэш: на не-unix межпроцессный lock — no-op, а Windows в релизе

**Проверка:** ✅ статически/сборкой (переатестация 2026-11-13) — `GOOS=windows go build ./...` собирается; `GOOS=windows go list -f '{{.GoFiles}}' ./internal/adapter/cache/` → `[disk.go id.go lock_other.go]`, т.е. в сборке пустые заглушки; `.goreleaser.yml` по-прежнему содержит `windows` (linux, darwin, windows).

**Статус:** 🟠 частично исправлено — ограничение задокументировано, код не менялся.
**Где:** `internal/adapter/cache/lock_other.go:7,11,13` (пустые `lockExclusive`/`unlockExclusive` и `tryLockExclusive`, всегда `true`, под `//go:build !unix`); `.goreleaser.yml` собирает windows; документация — `architecture.md:412` («cross-process lock is `flock(LOCK_EX)` and is **unix-only** … two non-unix processes can populate the same entry concurrently»), `docs/reliability-review.md`.
**Механика:** на Windows два процесса (или два «flight» одного ключа) не сериализуются: пишут один `dataRel+".tmp"` и `Rename` поверх → та же порча, что в D6, но без гонки. Реализации lock на Windows (`LockFileEx`) и проверки/отказа на старте при `GOOS=windows` с включённым кэшем нет.
**Направление:** реализовать блокировку на Windows (`LockFileEx`) либо предупреждать/падать на старте при windows + cache.enabled (документация уже есть — осталось поведение).
**Тест:** `GOOS=windows` — либо рабочий lock, либо отказ на старте.

---

## Прочие находки — проверено прогоном (`🟠`)

### D9 — legacy-ветка: `native`-читатель копирует `Salted__`-шифротекст как plaintext

**Проверка:** ✅ прогон (переатестация 2026-11-13) — `go test -run TestZZVERIF_D9_ ./internal/adapter/encrypt/`: `DecryptAuto(&Native{}, objEnc="", payload="Salted__…")` вернул `err=<nil>` и скопировал шифротекст как plaintext (31 байт, вывод == payload); `LegacyPlaintext(&Native{}, "Salted__") = true` — ranged-читатель тоже отдаёт шифротекст по байтам.

**Где:** `internal/adapter/encrypt/detect.go:59-81`: `decryptLegacy` — `:63-76` ветка `Passthrough` (mode=none) проверяет обе магии (`S3VLT01` `:64`, `Salted__` `:72`); `:77-79` ветка любого другого типа (в т.ч. `*Native`) — только `magicV1`; `:80-81` — всё остальное в `io.Copy` как plaintext.
**Механика:** containerless-объект с payload `Salted__` под читателем `mode=native` (без `S3VCTR01`) отдаётся как открытый текст, rc=0. **Смягчающий контур:** managed-фасад страхует — `fetch_profile.go:55-75` (`legacyEncryptor` через `LegacyKind`) в managed-режиме отказывает («containerless object is command ciphertext»), а gateway всегда идёт через `WithProfile` (`scope.go:183`, `fetch.go:126`). Не закрыты `DecryptAuto` и unmanaged-базовый `Fetch` (CLI-путь, `fetch_profile.go:81-82`). `architecture.md:338-340` обещает отказ для обеих магий без такой оговорки.

### D10 — namespace кэша не включает `s3.endpoint`/аккаунт

**Проверка:** ✅ unit (переатестация 2026-11-13) — `go test -run TestZZVERIF_D10 ./internal/config/`: два конфига (`endpoint=https://minio-a.example`/`userA` и `https://minio-b.example`/`userB`, bucket одинаковый) дают одинаковый `CacheNamespace()` и одинаковый `cache.ID` (`bc4ccf82…`).

**Где:** `internal/config/config.go:670-675` (`CacheNamespace()` для `BackendS3` возвращает только `c.S3.Bucket`); `internal/adapter/cache/id.go:15-21` (`cache.ID = SHA-256(namespace, backendKey, encFP)`); глобальный путь — `internal/cli/root.go:505` (`fetch.WithCache(d, cfg.CacheNamespace(), encFP)`), `internal/s3api/scope.go:58` (`cacheBucket` для static principal'ов); окно — `internal/service/fetch.go:368` (внутри `soft_ttl` hit отдаётся без S3 HEAD; дефолт `soft_ttl=20s`, `config.go:262`).
**Механика:** смена `s3.endpoint`/аккаунта при том же `bucket` и `cache.dir` → тот же `cache.ID` → старый plaintext отдаётся в окне `soft_ttl` (при совпавших ETag/sha — дольше). **Контраст:** per-user target'ы уже включают endpoint — `internal/adapter/s3target/profile.go:431-448` (`Namespace` = endpoint/region/bucket/prefix/accessKey); дыра только в глобальном пути `s3.*`.

### D11 — `max_sessions` вытесняет живую multipart-сессию

**Проверка:** ✅ прогон (переатестация 2026-11-13) — `go test -run TestZZVERIF_D11_ ./internal/s3api/`: **(A)** три неистёкших сессии (ttl=1h), у «живой» принята часть; sweep с `max=2` удаляет её каталог вместе с частью → `Get` = `os.ErrNotExist`, `Complete` ответит `NoSuchUpload`; **(B)** TOCTOU `get`→sweep→`spoolPart`: запись в снесённый каталог падает с ENOENT на `os.CreateTemp` — клиент получает 500, а не молчаливый 200; **(C)** стресс 300 мс: 0 успешных записей на вытесненной сессии, 278 × `ErrNotExist`. Подвариант «вытеснение по TTL в середине записи» по-прежнему опровергнут: `touch()` пинит сессию (`multipart.go:257`), `TestInFlightUploadPartPinsTheSession` проходит.

**Где:** `internal/s3api/session/registry.go:352-362`: при `len(live) > maxSessions` LRU-сессии удаляются (`delete` + `reg.remove` → `os.RemoveAll` каталога `:295-306`) **без проверки TTL и без пина in-flight** — попадают и только что активные сессии.
**Механика:** LRU-вытеснение сносит каталог сессии, которая ещё используется (между частями) → принятые части пропадают, `Complete` → `NoSuchUpload`. После D3-фикса окно `get`→sweep→`spoolPart` даёт чистый ENOENT/500, а не «200 на удалённые байты» — но исход «часть принята (200), затем каталог удалён» остаётся следствием самого вытеснения. Реальная проблема — только `max_sessions`.
**Направление:** при вытеснении по лимиту проверять TTL и не трогать сессии с in-flight операциями (пин, как у `touch()`).

---

## Прочее (не потеря данных, для полноты)

- **`New` сносит `.s3vault-tmp` конкурентного писателя.** `internal/adapter/local/store.go:102-106`: `root.RemoveAll(tmpDir)` безусловно в `New`; temp создаются там же (`:558-573` `createTemp`), commit через `s.root.Rename(tmp, rel)` (`:223`). **✅ прогон (механизм):** temp второго процесса исчез; первый писатель получает ошибку `Rename` — тихая потеря исключена, но конкурентные архивации в один каталог ломаются.
- **Нечитаемый авто-найденный конфиг → дефолты.** `internal/cli/root.go:115-140`: нечитаемый авто-найденный файл → `warning: ignoring unreadable config file …` в `os.Stderr` (`:137`, не в логгер — логгер инициализируется позже), чтение продолжается на дефолтах; явный `--config` при этом — жёсткая ошибка (`:134-136`). **✅ прогон:** `s3vault.yaml` с `encryption.mode: native` и `chmod 0000` → `mode` стал `none`. Поведение сознательное; решение о warning через логгер/жёсткой ошибке — за владельцем.

---

## Подтверждённые контракты (чинить нечего)

### D16 — `keying.FromRequestPath` схлопывает `..`

**Проверка:** ✅ прогон (переатестация 2026-11-13) — `go test -run TestZZVERIF_D16 ./internal/keying/`: `FromRequestPath("a/../b")` c `Prefix: "srv"` → `"srv/b"`; `"a/./b"` → `"srv/a/b"`; без префикса `"a/../b"` → `"b"`; `"../b"` и `"a/../../b"` → `invalid path` (валидация до join, выход за префикс невозможен).

**Где:** `internal/keying/mapper.go:52-61` → `ValidateRelative` (`internal/keying/prefix.go:19-45`, `path.Clean` `:35`).
**Механика:** `PUT/DELETE /bucket/a/../b` адресует объект `b` **в пределах своего префикса** — кросс-префиксной потери данных нет. Это зафиксированный краевой контракт нормализации ключа; хранится здесь, чтобы не «чинили» повторно.

---

## Отвергнутые варианты

Сюда попадает не «открытый дефект», а **осознанно отклонённое решение**: чтобы его не
предложили заново, нужно записать, почему оно хуже.

### MP1 — Fallback на одиночный `PutObject` в клиенте

**Статус:** 🚫 отвергнуто, не чинить.

Симптом, из которого он вырос: `archive` через шлюз падал на файле ~5+ МиБ с
`405 MethodNotAllowed` на `CreateMultipartUpload`. Первый очевидный обход — «узнать
один раз, умеет ли пир multipart, а при отказе спулить тело в temp-файл и сделать
одиночный `PUT`» — **не реализован и не должен быть**.

Две причины, каждая достаточна сама по себе:

1. **Ломает инвариант «клиент не знает про шлюз».** Поведение клиента начинает
   зависеть от возможностей пира — ровно тот класс глобальной подстройки одного под
   другим, из-за которого выкинули `archive.on_change`. Шлюз обязан предоставлять
   multipart, клиент обязан уметь в него писать.
2. **Не решает их задачу.** Одиночный `PUT` ограничен 5 ГиБ — это ограничение
   протокола (AWS: *«The largest object that can be uploaded in a single PUT is 5 GB»*),
   а не клиента. Обход починил бы диапазон 5 МиБ … 5 ГиБ и ничего больше, а у
   заказчика есть файлы больше 5 ГиБ.

Побочно подтвердилось при чтении SDK: повтор той же попытки невозможен и без probe —
`nextReader()` читает первые 5 МиБ **до** `CreateMultipartUpload`, тело пайпа не
перемотать. И одиночному `PutObject` нужен `Content-Length`: в
`smithy-go/transport/http/request.go` несеекабельный reader без `Len()` даёт
`ok = false` → `Content-Length = -1` → chunked, что S3 не принимает.

**Что сделано вместо этого:** multipart реализован в самом фасаде
(`internal/s3api/multipart.go`), клиент не изменён вообще — ни ключей конфигурации, ни
кода, ни поведения. Полное обоснование, пределы и путь для случая «хранилище шлюза не
умеет multipart»: `docs/multipart.md`.

---

## Как закрывать пункт

1. Воспроизвести или написать тест, который падает на текущем коде. Сохранить ссылку на него в пункте.
2. Отметить статус `✅` и кратко — что именно изменено и чем подтверждено.
3. Если правка меняет наблюдаемое поведение (заголовки, коды ответа, формат контейнера, коды выхода) — синхронно обновить `architecture.md` и, при наличии, `README.md` / `docs/`.
4. Не закрывать пункт «по описанию»: `architecture.md` — источник правды о **задумке**, `problems.md` — о том, что **расходится с ней или с кодом**. Расхождение устраняется одним из двух способов: починить код или исправить документ. Второе не считается исправлением бага, но иногда это правильный ответ.
5. Закрытый пункт удаляется из файла (история остаётся в git) — файл содержит только живой бэклог.
