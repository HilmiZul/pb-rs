# Compatibility contract

"Compatible" is defined narrowly and testably. Anything not listed here is not a
compatibility promise.

## Layers

| Layer | Requirement | Verified by |
|---|---|---|
| L1 CLI | `serve`, `superuser {create,update,upsert,delete,otp,ips}`, `migrate`, `version` accept the same flags and produce the same exit codes | scenario: CLI matrix |
| L2 On-disk | `pb_data/data.db` schema identical; `_migrations` rows identical; `_params.settings` byte-identical (incl. BLOB storage class); `_collections` identical modulo per-install secrets; installer superuser created on a fresh install | `tools/gate_m1.sh` |
| L3 HTTP | 54 routes, same methods, same status codes, same JSON envelope `{code,message,data}` | harness `basic` + per-domain scenarios; `tools/gate_m2.sh` for auth/settings/collections reads |
| L4 Auth | bcrypt hashes verify; JWT `HS256` with per-collection `authToken.secret`, claims `{collectionId,id,type,refreshable,exp}`; refresh, OTP, MFA, OAuth2, file tokens | cross-token test in `tools/gate_m2.sh`: a token minted by the oracle validates in the port and vice versa |
| L5 Query | filter/sort/expand/fields syntax and semantics, including NULL and relation traversal | differential fuzz of the filter parser |
| L6 Realtime | `text/event-stream` framing, `PB_CONNECT` event, subscription payloads | SSE scenario |
| L7 Static/UI | `/_/` serves the mirrored `ui/` tree with identical content types and SPA fallback | byte comparison of `ui/` |
| L8 JSVM | **not promised in v1** | — |

## Rules

1. **Normalization is explicit.** The harness replaces volatile values (record ids,
   timestamps, JWTs, secrets) with placeholders before comparing. A new
   normalization rule must be reviewed, because it can hide a real difference.
   The at-rest gate normalizes exactly two things: the 50-char `[A-Za-z0-9]` token
   secrets inside `_collections.options`, and the installer superuser's
   `id`/`password`/`tokenKey` (which are checked for shape instead of equality).

   The HTTP harness normalizes: JWTs, 50-char secrets, 15-char record ids,
   timestamps, and the 10-char random suffix that
   `GET /api/collections/meta/scaffolds` regenerates on every request
   (`collectionScaffolds` calls `security.RandomStringWithAlphabet(10, ...)` and
   embeds it in the default index names). The rule only matches index names
   followed by `` ON `` `` — i.e. the scaffold's empty table name — so real
   collection index names are still compared exactly.
2. **JSON key order is not a contract.** Comparisons are semantic (parsed JSON).
3. **Error text is a contract.** The admin UI and SDKs surface `message` strings;
   they are compared verbatim.
4. **Response headers**: `content-type` is compared; the rest are recorded but not
   enforced in v1.
5. **Unknowns are recorded, not guessed.** When the oracle cannot be made to reveal
   behaviour (e.g. a code path requiring an external SMTP server), the gap is listed
   in `docs/UNKNOWNS.md` rather than filled with an assumption.

## Deliberate divergences

Each entry states what differs, why, and which gate proves the difference is
harmless. Everything not listed here is expected to match the oracle exactly.

### D1 — Historical migrations are not replayed

A fresh install is created directly at the v0.40 schema shape; the intermediate
v0.22 → v0.23 transformations (`1717233556..1717233559`) are not executed. The
eight `_migrations` rows are still recorded, so the oracle sees a fully migrated
database and never re-runs them.

*Why:* replaying history would add a large amount of code whose only output is the
final schema, which is already reproduced verbatim from the oracle.
*Proven harmless by:* gate phase 1 (schema + `_migrations` identical) and phase 3
(the oracle opens a port-created install without re-running anything).

### D2 — `sqlite_stat1`/`sqlite_stat4` are not pre-created

The oracle's `PRAGMA optimize` materializes the planner stat tables at slightly
different moments, so their presence and row order are not stable even between two
oracle runs. The gate excludes `sqlite_stat*` from schema comparison.

*Why:* these tables are SQLite planner artifacts, not application data.
*Proven harmless by:* gate phase 1 (filtered schema diff is empty in both
directions); a port-opened oracle database keeps its stat tables untouched.

### D3 — `_defensive=1` is not set

The oracle's DSN passes `_defensive=1` (mattn/go-sqlite3). The bundled SQLite in
`rusqlite` does not expose `sqlite3_db_config(SQLITE_DBCONFIG_DEFENSIVE)`, so the
port sets every other pragma (`busy_timeout`, `journal_mode`, `journal_size_limit`,
`synchronous`, `foreign_keys`, `temp_store`, `cache_size`) but not this one.

*Why:* no available API in the chosen SQLite binding.
*Impact:* the flag only blocks writes to shadow tables and `PRAGMA writable_schema`.
Application-level behaviour is unaffected; a client cannot reach these knobs
through the REST API.

### D4 — Request logging is not implemented yet

The oracle appends one `_logs` row per HTTP request to `auxiliary.db`. The port
does not log yet, so a port-opened install accumulates no new log rows. The gate
therefore compares `auxiliary.db` **schema only** for fresh installs, and full row
equality for the drop-in direction (where both sides start from the same rows).

*Status:* pending, tracked for M5 (`/api/logs` + log retention).

### D5 — Installer superuser password is random and unknown

Both binaries create `__pbinstaller@example.com` with a random password and
`tokenKey`, so those three values can never match across installs. The gate checks
their *shape* (`id` = 15 lowercase alnum, `tokenKey` = 50 alnum, `password` =
`$2a$10$` bcrypt) and asserts they are not copied from the oracle.

*Why:* the values are per-install secrets by design.
*Proven harmless by:* gate phase 1 (installer row check) — the row exists exactly
when the oracle would create it, so the installer flow is triggered identically.

### D6 — Collections-list `filter` is not implemented yet

`GET /api/collections?filter=...` currently answers 400
("Something went wrong while processing your request.") for any non-empty
filter, because the search filter language is not ported yet. The oracle
evaluates the filter against the whitelisted collection fields.

*Why:* the filter expression parser is a whole subsystem and belongs with the
records query work (M2b/M3).
*Status:* pending M2b. The admin UI's collections page does not send a filter on
load (it uses `page`/`perPage`/`skipTotal`), so the M2 gate is unaffected.

### D7 — JS migrations and hooks are not executed

The oracle's default JS migrations directory is `<dataDir>/../pb_migrations`
(`plugins/jsvm`), and API collection changes are written there as `*.js` files.
The port has no JSVM in v1, so those files are ignored: a database whose schema
was produced by JS migrations must already contain the resulting collections.

*Why:* the JSVM (goja) is explicitly out of scope for v1 (tier (a) covers the API
and the data model).
*Impact:* an install migrated only through JS files will look empty to the port.
Probe/test installs must therefore be isolated per parent directory — a shared
parent makes one install's auto-generated migrations leak into another, which is
what the M2 gate now avoids by nesting each install under its own root.
*Status:* pending v2 (JSVM). Revisit before claiming "hooks compatible".

### D8 — JSON request bodies are matched case-sensitively

The oracle decodes JSON with `json.MatchCaseInsensitiveNames(true)`, so
`{"META":{"APPNAME":"X"}}` updates `meta.appName`. The port's `serde`
deserializers match keys exactly, so such a body is silently ignored (unknown
keys are always ignored by both sides).

*Why:* serde has no wildcard case-insensitive field matching; emulating it needs
a normalisation pass over every bound body against a canonical key skeleton.
*Impact:* only hand-written clients that rely on non-canonical casing. The admin
UI always sends the exact camelCase keys.
*Status:* recorded; may be ported later with the shared request-binding layer.
