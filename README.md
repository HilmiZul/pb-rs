# PocketBase-compatible server in Rust

> This PocketBase (Rust) I used for my personal side project. I really love PocketBase project: simple. lightweight. fast.
Thanks to Gani Georgiev for creating this cool project.

A from-scratch Rust implementation of the PocketBase HTTP/data layer, built to be a
**drop-in replacement**: it must open an existing `pb_data/` directory, serve the
original admin UI, and answer the official SDKs exactly like the Go binary does.

The Go binary is the **oracle**. Every behavioural claim in this project is checked
against it by a differential harness — not by reading documentation.

## Hard constraints (decided up front)

| # | Constraint | Consequence |
|---|---|---|
| 1 | **Drop-in `pb_data`** | the SQLite schema, migration chain, ids, token secrets and on-disk layout must match byte-for-byte |
| 2 | **Reuse the original admin UI** | the embedded SvelteKit build from the Go binary is served unchanged; it defines the API contract |
| 3 | **JSVM is out of scope for v1** | `pb_hooks` (goja) is deferred; API/data parity comes first |
| 4 | **No decompiler dependency** | the binary is stripped but not trimpath'd: pclntab names + source paths + build info are recovered directly |

## Oracle identity

```
release   v0.42.3  (ganigeorgiev.com/pocketbase/pocketbase)
source    ganigeorgiev.com/pocketbase/pocketbase@v0.42.3
commit    c5003ce63deee71cc6821f338f0d4e1994b3db40
download  https://ganigeorgiev.com/meta/pocketbase/pocketbase/download/v0.42.3/pocketbase_0.42.3_darwin_arm64.zip
zip sha256 232c0d5bbb05185b70eb8b37fa3cd8be0ae9b5ae5cf94cbec6d93f98733e0893
binary sha256 1b046021fd7c9d060ec1cb7d1bdcd00fcb16e998f246516ed87173f315dff0f9
build     Go 1.27.4, darwin/arm64, CGO_ENABLED=0, -s -w
```

`vcs.modified=false` — the shipped binary is an unmodified upstream build, so the
upstream source at that commit is valid semantic reference material (MIT licensed).

> v0.40.6 was the last release published on GitHub. v0.41.0 and later live only on
> `ganigeorgiev.com`; the Go module path also changed from
> `github.com/pocketbase/pocketbase` to `ganigeorgiev.com/pocketbase/pocketbase`.
> The previous baseline (v0.40.6, commit `9d281cca`) is still available in
> `.upstream/` for deltas.

## Layout

```
harness/            differential harness (record oracle, diff port)
harness/scenarios/  request scenarios
spec/               machine-readable specs extracted from the oracle
  routes-full.tsv       54 API routes: method, path, handler, middleware
  routes-verified.tsv   same routes, probed live against the oracle
  schema.sql            exact DDL of a fresh pb_data/data.db
  system/               settings seed, system collections, migrations, field types,
                        validation keys, JSVM typings
ui/                 embedded admin UI, mirrored 1:1 from the oracle (97 files)
tools/              extraction scripts (re-runnable)
docs/               plan and compatibility contract
```

## Quick start

```bash
# 1. boot the oracle in a throwaway data dir
~/lab/pb/pocketbase serve --http=127.0.0.1:18090 --dir=.oracle/data &

# 2. record golden responses
cargo run -q -p harness -- record \
  --base http://127.0.0.1:18090 \
  --scenario harness/scenarios/basic.json \
  --out .oracle/golden

# 3. later, diff the Rust port against the same goldens
cargo run -q -p harness -- diff --a .oracle/golden --b .oracle/port
```

## Status

**M0 complete** — spec extraction and harness foundation.
Next: **M1** (bootstrap + schema + migration-chain parity, opens existing `pb_data`).
See `docs/PLAN.md`.

## License

MIT, same as upstream PocketBase. The embedded admin UI in `ui/` and the extracted
specs derive from PocketBase (c) Gani Georgiev and contributors; see `LICENSE.md`.
This project is not affiliated with or endorsed by the PocketBase project.
