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

## M1 — Bootstrap, schema, migration parity  ← next

Scope: CLI skeleton (`serve`, `version`), config/flag parsing identical to cobra's,
SQLite open with the same pragmas, `_migrations` chain replay, `_params` seeding,
`_collections` seeding for `_superusers` + `users`.

**Gate:**
1. Point the Rust binary at a `pb_data/` created by the Go binary → it starts and
   serves `/api/health`.
2. `sqlite3 .schema` diff (both directions) is empty.
3. `_migrations`, `_params`, `_collections` row dumps are identical after
   Rust-then-Go and Go-then-Rust round trips.

## M2 — Collections, settings, superuser login

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
