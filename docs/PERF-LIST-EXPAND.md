# Record list + expand performance

Why the port was slower than the Go oracle on the admin UI's `pemetaan` list
request, what was changed, and what the measurements show now.

The short version: **Rust is not the reason**. The port rebuilt collection,
filter, visibility and expand metadata *per request* and *per record*; the
oracle keeps parsed collections in memory and expands a page with one query per
expand path. After mirroring those two behaviours the port is faster than the
oracle on every measured list/expand case.

## 1. What was measured

The exact request the admin UI issues for `pemetaan` (473 rows, 32 collections,
7 fields):

```
GET /api/collections/pemetaan/records
    ?page=1&perPage=40&skipTotal=1&sort=-@rowid
    &expand=iduka,siswa,program_keahlian
```

Method: both servers on the same machine, same dataset copied from
`target/release/pb_data`, superuser auth, 30 warm-up requests then 300 timed
requests over one keep-alive connection (p50 unless stated otherwise). The Go
binary is PocketBase v0.42.3 (`~/be`); the Rust binary is
`cargo build --release -p pb-cli`.

Reproduce with the script shape in §8.

## 2. Root causes (measured, not guessed)

### C1 — `filter_context` rebuilt on every request

`filter_context()` walked **every collection** in the database to build
`relations`, `collections`, `base_types` and the allowed-field list, then threw
it away. Cost: **1.0–1.2 ms per call** on this dataset, and it was called once
per list request *and* once per expanded relation.

Scaling check: duplicating the collection metadata to 128 collections grew a
plain list request from **1.5 ms to 4.82 ms** — the cost tracked the number of
collections, not the number of rows.

The oracle calls `FindCachedCollectionByNameOrId` and gets a pointer into an
already-parsed `[]*Collection`. It never re-parses `fields`/`options` JSON.

### C2 — expand was per record × per relation

The old expander looped over records, then over relation fields, and for each
pair it did:

* `Collection::find` (parse the collection row again),
* `filter_context` (walk all collections again),
* `RecordModel::find_by_id` (one query **per relation id**),
* a fresh expand tree parse.

With 40 records × 3 expansions that is 120 collection lookups, 120 filter
contexts and up to 120 single-row queries. The oracle uses
`FindRecordsByIds` once per expand path (see
`.upstream/core/record_query_expand.go`).

### C3 — per-record collection clone and visibility rebuild

`RecordModel` owned a `Collection` by value, so every row deep-cloned the parsed
fields/options/indexes. Visibility was also rebuilt per record even though a
superuser sees every field of every record.

Per-record cost of row decoding + JSON export: **17 µs for 7 fields, 41 µs for
17 fields**, versus the oracle's 7 µs / 16 µs.

### C4 — `BTreeMap` sort on every export

`to_api_json_with` collected the export map into a `BTreeMap` and inserted into
a fresh `serde_json::Map` to get alphabetically sorted keys, and `get_json`
re-scanned the collection for each field name. Both are per record.

### C5 — debug build in the comparison

The debug binary was **7–8x slower** than release (admin UI request: 1117 ms vs
145 ms). Some early "Rust is slow" observations were mostly this.

## 3. Changes

### P0 — shared collection registry (`crates/pb-core/src/collections.rs`)

* `CollectionRegistry` holds `Arc<Collection>` values indexed by id and name,
  plus one `Arc<Vec<Arc<Collection>>>` for `FindAllCollections`.
* Keyed by **database path** (`Connection::path()`), not connection address:
  pooled `rusqlite::Connection` values move in and out of the pool, so their
  address is not a stable identity.
* `GENERATION: AtomicU64` is bumped by `invalidate_cache()`; downstream caches
  compare it.
* `find_shared()` / `load_all_shared()` are the read paths. `load_all()` stays
  uncached on purpose: write paths (transactions, schema sync) must observe
  their own uncommitted `_collections` rows.
* `Db::open` invalidates the registry so a reopened data directory never reuses
  a stale view.

### P0 — cached filter context (`crates/pb-api/src/records.rs`)

`FILTER_CACHE` stores `Arc<FilterContext>` per `(database path, collection id,
include_hidden)` and drops every entry when the collection generation changes.
`filter_context()` now returns `Arc<FilterContext>`; `build_filter_context()`
keeps the old construction code for cache misses and in-memory databases.

### P1 — shared `RecordModel` collection

`RecordModel.collection` is now `Arc<Collection>`; `new_shared`,
`from_row_shared` and `find_by_id_shared` avoid the per-row deep clone and use
`prepare_cached`. Column names are borrowed from the statement instead of being
copied into `Vec<String>`.

### P1 — batch expand

`expand_records()` mirrors the oracle:

1. per expand path, collect the relation ids of the whole page (deduplicated),
2. one `SELECT * FROM … WHERE id IN (…)` per path (`fetch_records_by_ids`,
   chunked at 400 parameters),
3. recurse into the child tree with the same batching,
4. fill each record's `expand` object afterwards.

Cost is now O(#expand paths), not O(#records × #relations). The single-record
`expand_record()` used by view/get handlers is a one-element wrapper.

### P1 — hoisted visibility + cheaper export

Superuser visibility is computed once per page (and once per expanded
collection) via `superuser_visibility()`. `to_api_json_with` sorts a `Vec` with
`sort_unstable_by` and converts the field value in place instead of using a
`BTreeMap` + `get_json` re-scan.

### P2 — prepared statement for the list query

The list `SELECT … LIMIT ? OFFSET ?` uses `prepare_cached`; the admin UI repeats
the same SQL text between requests.

### Not done (deliberately)

* **Settings cache.** `settings::load` is called twice per record request (global
  and collection rate-limit middleware). The stored blob is ~1.1 KB and parsing
  it is on the order of tens of microseconds; a cache would need invalidation on
  `save`, `save_raw` and restore, which is more risk than the measured gain.
  Revisit if rate-limit settings grow.
* **Statement-cache sizing.** `prepare_cached` keeps the default small cache; with
  many collections it can evict, but a miss only re-prepares one statement.

## 4. Results (release build, p50 per request)

| case | Go | Rust before | Rust after | after / Go |
|---|---:|---:|---:|---:|
| admin UI: 40 rows + 3 expands | 2.40 ms | 144.85 ms | **1.31 ms** | 0.55x |
| list 30 | 0.39 ms | 1.88 ms | **0.36 ms** | 0.93x |
| list 200 | 1.74 ms | — | **1.05 ms** | 0.60x |
| list 1000 | 3.56 ms | 9.41 ms | **2.14 ms** | 0.60x |
| `siswa` list 200 | 3.37 ms | — | **1.83 ms** | 0.54x |
| filter `id != ''` | 0.39 ms | — | **0.35 ms** | 0.90x |

Rust p95 tracks p50 closely (admin UI 1.36 ms), so the win is not a warm-cache
artifact.

8 threads, 5 s per run:

| workload | Go | Rust | ratio |
|---|---:|---:|---:|
| admin UI list + 3 expands | 1279 rps | **3161 rps** | 2.47x |
| plain list 30 | 7656 rps | **12731 rps** | 1.66x |

The before/after ratio on the admin UI request is ~110x; the dominant share came
from C1 (filter context) and C2 (per-record expand), not from row decoding.

## 5. Correctness evidence

`cargo test -p pb-core -p pb-api`: 121 tests pass.

Differential harness (Go oracle vs Rust, fresh data dir per scenario):

```
m3c-expand-fields      30 responses, 0 mismatches
m3-records-basic       10 responses, 0 mismatches
m3b-filter-basic       21 responses, 0 mismatches
m3d-rules              22 responses, 0 mismatches
m3g-fields             45 responses, 0 mismatches
m3h-auth-visibility    50 responses, 0 mismatches
```

`m3c-expand-fields` covers `list-expand-author`, `list-expand-nested`,
`list-expand-multi`, `get-expand`, `list-fields-expand`,
`list-filter-relation` and the multi-relation filter operators.

## 6. Known differences that are *not* from this work

Verified by building `HEAD` in a separate worktree and comparing it with the
oracle on the same dataset. All three reproduce on `HEAD`:

* `expand=<unknown field>`: the oracle omits the `expand` key, the port emits
  `expand: {}`.
* `expand=siswa.rombel` when `rombel` is not a relation of `siswa`: the oracle
  drops the whole path, the port still expands `siswa`.
* A relation filter without an explicit `sort` returns the same 473 rows in a
  different order (different tie-break order).

These are pre-existing compatibility gaps; they are unrelated to the caching
and batching changes.

## 7. Guidance

* Keep read paths on `find_shared` / `load_all_shared`; use `Collection::find` /
  `load_all` only inside transactions that may not have committed yet.
* Any new code that mutates `_collections` must call
  `Collection::invalidate_cache()`; that single call also invalidates the filter
  context cache.
* Do not key caches by `&Connection`/pointer. Pooled connections move, and
  in-memory databases have no path, so those paths must stay uncached.
* Benchmark release builds only.

## 8. Reproduction

```bash
# terminal 1 — oracle
cd ~/app
./be serve --http=127.0.0.1:18611 --dir "$TMP/go/pb_data"

# terminal 2 — port
cd ~/pb-rs
./target/release/pocketbase serve --http=127.0.0.1:18612 --dir "$TMP/rust_pb_data"
```

Then drive the request in §1 with the superuser token, 30 warm-ups and 300
timings; or run the harness:

```bash
./target/release/harness record --base http://127.0.0.1:18611 \
  --scenario harness/scenarios/m3c-expand-fields.json --out /tmp/go-m3c.json
./target/release/harness record --base http://127.0.0.1:18612 \
  --scenario harness/scenarios/m3c-expand-fields.json --out /tmp/rust-m3c.json
./target/release/harness diff --a /tmp/go-m3c.json --b /tmp/rust-m3c.json
```

Use a fresh `--dir` per scenario so collection names do not collide.
