# Plan

Milestones are gated: a milestone is done only when its gate passes against the
oracle. No milestone is skipped, and no gate is "mostly passing".

## M0 — Spec extraction + harness foundation  ✅ done

Deliverables:
- `spec/routes-full.tsv` — 54 API routes with handler + middleware, extracted from the
  source tree at the binary's `vcs.revision`.
- `spec/routes-verified.tsv` — the same table probed live (50/54 answer; the 4 remaining
  404 at the resource level and are recorded as such, not as missing routes).
- `spec/schema.sql` — exact DDL of a fresh `data.db`.
- `spec/system/` — settings seed, system collections (fields/indexes/rules/options incl.
  all auth token secrets + durations), migration chain, field types, validation keys,
  JSVM typings.
- `ui/` — the embedded admin UI mirrored 1:1 (94/94 files verified present).
- `harness/` — `record` + `diff` with explicit normalization.

**Gate (passed):** the harness records the oracle and self-diffs with 0 mismatches
(9 responses), proving the recorder and normalizer are deterministic.

## M1 — Bootstrap, schema, migration parity  ✅ done

Scope: CLI skeleton (`serve`, `version`), config/flag parsing identical to cobra's,
SQLite open with the same pragmas, `_migrations` chain replay, `_params` seeding,
`_collections` seeding for `_superusers` + `users`, installer superuser bootstrap.

Deliverables:
- `crates/pb-core` — `db` (pragma set from `core/db_connect.go`), `migrations`
  (8-entry chain), `seed` (settings + 6 system collections), `superusers`
  (`__pbinstaller@example.com`), `ids` (id/secret generation).
- `crates/pb-api` — `/api/health`, JSON 404 envelope, `/_/` static serving.
- `crates/pb-cli` — cobra-compatible flags, `serve`, `--version`.
- `tools/gate_m1.sh` + `tools/gate_m1_compare.py` — the automated gate.

**Gate (passed):** `tools/gate_m1.sh`, 24 checks in three phases:

1. *Fresh install*: `data.db` schema identical modulo `sqlite_stat*`; `_migrations`
   set identical (8); `_params.settings` **byte-identical**; `_collections` rows
   identical modulo the per-install token secrets; secrets regenerated (50 chars);
   installer superuser row matches (`email`/`verified`/`emailVisibility`, bcrypt
   `$2a$10$` hash); JSON columns share SQLite storage classes (BLOB vs TEXT);
   `auxiliary.db` schema identical; both write `types.d.ts`.
2. *Drop-in*: the port opens an oracle-created install and changes no schema and no
   row in either database.
3. *Reverse drop-in*: the **oracle** opens a port-created install, starts, answers
   `/api/health`, and does not re-run migrations or touch `data.db`.

## M2 — Collections, settings, superuser login  ← next

Scope: `_collections` CRUD, field builder validation, import/export, scaffolds,
`/api/settings` read/write, superuser auth, `/_/` static serving.

**Gate:** the real admin UI (from `ui/`) logs in, lists collections, and renders the
settings page against the Rust server.

## M3 — Records CRUD, filter/sort/expand, rules

Scope: record list/view/create/update/delete, `filter`/`sort`/`expand`/`fields`,
collection rules (`@request.auth`, `@collection.*`), rate limits.

**Gate:** differential filter fuzz (generated expressions over a fixed dataset) with
zero semantic differences; expand output byte-identical after normalization.

## M4 — Auth, files, tokens

Scope: password, OTP, OAuth2, MFA, email change/verification/password reset,
`_externalAuths`, `_authOrigins`, file tokens, thumbnails incl.
`PB_THUMBS_MAX_SOURCE_PIXELS`.

**Gate:** cross-implementation token acceptance in both directions; bcrypt
verification of hashes produced by the oracle.

## M5 — Realtime, batch, backups, logs, crons

**Gate:** an official SDK client connects over SSE and receives identical events;
batch transaction semantics match under partial failure.

## M6 — JSVM (deferred)

Only after M1–M5 are green. Target: documented hook surface, not full goja parity.

## M7 — Hardening

Fuzz the filter parser, load test, audit the rules engine, document every remaining
unknown in `docs/UNKNOWNS.md`.
