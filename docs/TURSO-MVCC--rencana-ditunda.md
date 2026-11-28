# Turso + MVCC: Kajian Kelayakan dan Opsi Implementasi

**Status:** DITUNDA — bahan pertimbangan, belum disetujui untuk dieksekusi.
**Tanggal:** 28 November 2026
**Proyek:** `pb-rs` — PocketBase-compatible server in Rust (baseline oracle v0.42.3)
**Tujuan asal:** meningkatkan performa concurrency tulis.

> Dokumen ini sengaja disimpan sebagai *decision record*, bukan rencana eksekusi aktif.
> Jika nanti dipilih untuk dikerjakan, pindahkan ke `docs/TURSO-MVCC.md` dan ubah statusnya.

---

## 1. Ringkasan eksekutif

| Pertanyaan | Jawaban |
|---|---|
| Mungkinkah Turso di proyek ini? | Mungkin secara teknis, tetapi mahal. Turso kompatibel dengan file SQLite, tetapi crate `turso` masih 0.8.x (belum 1.0), API-nya async, dan MVCC masih beta. |
| Harus rewrite banyak? | Ya. Bukan seluruh logika, tetapi seluruh lapisan akses DB: 28.063 baris Rust, 93 fungsi ber-`&Connection`, 47 `query_row`, 43 `row.get`, 15 `prepare`, 7 `prepare_cached`, 4 `transaction`, plus error translation dan PRAGMA yang tidak didukung. |
| Bisa jadi toggle di Setting Admin UI? | Tidak disarankan. Empat penghalang keras: UI adalah bundle upstream, `_params.settings` harus byte-identical, MVCC mengubah header file sehingga oracle SQLite tidak bisa membukanya, dan toggle butuh restart. |
| Fitur Setting vs branch baru? | Branch/feature-gate lebih baik. Toggle UI adalah opsi terburuk. Rekomendasi: default tetap SQLite; Turso sebagai backend opsional di balik cargo feature + flag CLI. |
| Apa yang harus disiapkan? | Benchmark baseline, compatibility harness, tool konversi + backup, retry semantics, CI matrix, dan keputusan menerima risiko. |

**Kesimpulan:** Jangan mulai dari Turso. Ukur dulu (F0), optimalkan SQLite (F1), lalu spike Turso terpisah (F2). Implementasi penuh (F3) hanya jika spike membuktikan keunggulan yang jelas. Toggle Admin UI (F4/D) tidak direkomendasikan.

---

## 2. Fakta pembatas (terverifikasi)

| Fakta | Sumber | Dampak |
|---|---|---|
| `PRAGMA journal_mode='mvcc'` mengubah byte header file DB. SQLite stok menolak dengan `file is not a database`. Kembali ke `wal` memulihkan kompatibilitas. | Blog Turso v0.4.0; catatan teknis MVCC | Melanggar hard constraint #1 (drop-in `pb_data`). Oracle PocketBase tidak bisa membuka `pb_data` saat MVCC aktif. |
| Turso: "We don't support mixed SQLite and Turso in multi-process scenarios." | COMPAT.md, Guarantees #4 | `tools/load_wal.py` (koneksi SQLite eksternal), backup/restore, dan oracle tidak bisa berjalan berdampingan. |
| Multi-process WAL Turso masih `experimental_multiprocess_wal` (default off). | `bindings/rust/src/lib.rs` | Bahkan mode WAL Turso bukan pengganti drop-in untuk SQLite stok. |
| Crate `turso` async; tidak ada `query_row`, tidak ada `FromSql`, `Row::get_value() -> Value`, tidak ada `create_function` (stub C API). | docs.rs 0.8.x; source `bindings/rust/src/connection.rs` | 93 fungsi sinkron harus jadi async, atau dibungkus worker-thread + channel. |
| PRAGMA gap: `journal_size_limit` ❌, `optimize` ❌, `wal_checkpoint` dengan parameter partial, `VACUUM` in-place experimental, `PRAGMA_TABLE_INFO` (TVF) tidak terdaftar. | COMPAT.md | `db.rs`, `crons.rs`, `records.rs` (VACUUM), `view.rs` (TVF) harus diadaptasi/diverifikasi. |
| Admin UI yang diserve adalah 97 file build (`ui/`); sumber hanya ada di `.upstream/ui/src` yang gitignored. | `git ls-files ui`; `.gitignore` | Menambah toggle = vendoring + rebuild SvelteKit, dan mematahkan L7 (byte-compare `ui/`). |
| `_params.settings` harus byte-identical (gate M1). | `docs/PLAN.md`, `docs/COMPATIBILITY.md` | Key baru di settings mematahkan gate; oracle akan membuang key itu saat PATCH settings. |
| MVCC = snapshot isolation; konflik tulis dideteksi saat COMMIT. | Docs Turso, `BEGIN CONCURRENT` | Setiap transaksi tulis harus `BEGIN CONCURRENT` + retry; jika tidak, error 500 saat kontensi. Perlu audit write-skew. |
| Pool saat ini 32 koneksi data + 8 aux, tumbuh tak terbatas saat habis; DB call sinkron di dalam handler async (hanya activity log yang `spawn_blocking`). | `crates/pb-api/src/auth.rs`, `crates/pb-api/src/activity.rs` | Ada optimasi concurrency yang jauh lebih murah daripada ganti engine. |
| Turso 0.8.4 (20 Nov 2026), 0.9.0-pre.6 (20 Nov 2026); docs.rs gagal build untuk 0.8.4. | crates.io / docs.rs | Churn pre-1.0; pin versi exact dan siap menghadapi breaking change. |

---

## 3. Analisis opsi

| Opsi | Perubahan | Risiko | Manfaat | Rekomendasi |
|---|---|---|---|---|
| **A. Optimasi SQLite (tanpa Turso)** | Kecil–sedang: cap pool, `spawn_blocking`, perpendek transaksi, retry `SQLITE_BUSY`, tuning checkpoint | Rendah | Menghilangkan bottleneck nyata lebih dulu; tetap 100% drop-in | **Lakukan lebih dulu** |
| **B. Spike Turso terpisah** | Crate/tool kecil; baca salinan `pb_data` | Rendah (tidak menyentuh main) | Mengukur throughput & kompatibilitas dengan data nyata | **Gerbang keputusan** |
| **C. Backend Turso feature-gated** | Besar: facade DB + port 93 fungsi + flag CLI + tool konversi | Tinggi | MVCC untuk beban write-heavy; default tetap SQLite | Hanya jika B menang |
| **D. Toggle di Admin UI** | C + fork/rebuild UI + key settings baru | Sangat tinggi | UX paling nyaman, tetapi merusak parity & drop-in | **Tidak disarankan** |

### Mengapa bukan toggle "SQLite WAL vs Turso MVCC"?

Framing itu menyesatkan:

1. MVCC hanya ada di engine Turso; rusqlite/SQLite tidak bisa melakukannya. Jadi pilihannya adalah **engine**, bukan sekadar journal mode.
2. Setelah MVCC aktif, file bukan lagi SQLite yang bisa dibuka oracle. Ini bertentangan dengan tujuan utama proyek (drop-in `pb_data`).
3. Journal mode bersifat persisten per file dan harus diset sebelum transaksi; tidak bisa diubah saat server berjalan. Toggle di UI hanya bisa berarti "simpan pilihan → restart".
4. WAL di Turso pun bukan SQLite stok (multi-process masih experimental).

### Mengapa gain MVCC mungkin kecil di sini

- SQLite WAL sudah memberi **banyak reader paralel + satu writer**. MVCC hanya menambah paralelisme **writer**.
- PocketBase umumnya read-heavy; bottleneck terukur sebelumnya justru per-request collection/expand, bukan pool (lihat `docs/PERF-LIST-EXPAND.md`).
- Port sudah lebih cepat dari oracle pada kasus list/expand terukur (1,31 ms vs 2,40 ms p50; 3161 vs 1279 req/s over 8 threads).

---

## 4. Rencana bertahap (usulan, belum dieksekusi)

### F0 — Ukur dulu (wajib, sebelum keputusan apa pun)

- Benchmark campuran read/write, konkurensi 8/32/64.
- Metrik: throughput, p50/p95, rate `SQLITE_BUSY`, waktu tunggu write lock.
- Bandingkan dengan oracle Go pada skenario yang sama.
- **Gate:** laporan baseline tersimpan di `docs/DB-CONCURRENCY-BASELINE.md`.

### F1 — Optimasi SQLite (murah, aman)

- Cap ukuran pool + antrean/`Semaphore` (jangan buka koneksi tanpa batas).
- Pindahkan kerja DB berat ke `spawn_blocking` (atau `block_in_place`).
- Perpendek cakupan transaksi tulis.
- Retry/backoff terpusat untuk `SQLITE_BUSY`.
- Audit `prepare_cached`, `wal_autocheckpoint`, `journal_size_limit`.
- **Gate:** `tools/gate_m7.sh` + load test tetap 0 error; skema/byte `pb_data` tidak berubah.

### F2 — Spike Turso (tanpa menyentuh main)

- Crate terpisah: buka **salinan** `pb_data`, jalankan skenario CRUD + filter + transaksi.
- Verifikasi: `sqlite_master`, `PRAGMA table_info`, `_migrations`, `_params` byte, `integrity_check`, trigger/view/ALTER TABLE, `VACUUM INTO`.
- Ukur throughput MVCC (`BEGIN CONCURRENT`) vs WAL pada beban yang sama.
- **Gate:** laporan kompatibilitas + angka. Jika tidak menang jelas → stop; simpan temuan di `docs/UNKNOWNS.md`.

### F3 — Backend Turso opsional (hanya jika F2 menang)

- Cargo feature `turso-backend`; flag `--db-engine sqlite|turso` + `--journal-mode wal|mvcc`.
- **Strategi porting hemat risiko:** facade `DbConn` sinkron yang membungkus runtime Turso di thread khusus (pola seperti `pb-js`), sehingga 93 fungsi tidak perlu diubah menjadi async. Alternatif: port penuh ke async (lebih bersih, lebih mahal).
- Tool `migrate --to-mvcc` / `--to-wal`: backup `VACUUM INTO` dulu, flip header, `integrity_check`, restart.
- Retry `BEGIN CONCURRENT` di semua jalur tulis.
- **Gate:** seluruh gate M1–M8 versi Turso (subset), plus gate SQLite default tetap hijau.

### F4 — UI (opsional, terpisah)

- Jika tetap ingin toggle: **bukan** di `settings` PocketBase. Simpan di file konfigurasi/env, tampilkan di halaman kustom (butuh fork UI) dengan status "restart to apply".
- Jika tidak: cukup CLI/flag. Tidak ada perubahan `ui/`, L7 tetap aman.

---

## 5. File yang akan terdampak jika F3 dikerjakan

- `crates/pb-core/Cargo.toml` — dependency `turso` (optional feature).
- `crates/pb-core/src/db.rs` — pemilihan engine, pragma, `journal_mode=mvcc`; hapus registrasi math (Turso punya built-in).
- `crates/pb-core/src/lib.rs` — re-export facade, bukan `rusqlite`.
- 93 signature `&Connection` di `schema_sync.rs`, `records.rs`, `record_upsert.rs`, `record_delete.rs`, `superusers.rs`, `search.rs`, `migrations.rs`, `settings.rs`, `collection_write.rs`, `collections.rs`, `view.rs`, `seed.rs`.
- `crates/pb-api/src/auth.rs` — implementasi pool (async / thread-per-conn).
- `crates/pb-api/src/{records,collections,settings,sql,backups,crons,batch,auth}.rs`.
- `crates/pb-cli/src/main.rs` — bootstrap, flag engine, perintah konversi.
- `crates/pb-core/src/schema_sync.rs` — translasi error Turso (saat ini `rusqlite::Error::SqliteFailure`, kode 19/2067).
- `crates/pb-core/src/view.rs` — pengganti `PRAGMA_TABLE_INFO`.
- `crates/pb-api/src/backups.rs` — `VACUUM INTO` (didukung) + jalur restore.
- `crates/pb-api/src/crons.rs` — `VACUUM`, `wal_checkpoint(TRUNCATE)` (divergensi).
- `tools/load_wal.py` — parameterisasi journal mode + batasan multi-process.
- `docs/COMPATIBILITY.md`, `docs/UNKNOWNS.md`, README (tabel hard constraint).

---

## 6. Checklist persiapan

1. Benchmark harness yang bisa dijalankan ke dua engine (F0).
2. Compatibility harness Turso: skema, `_migrations`, `_params` byte, `integrity_check`, trigger/view/ALTER.
3. Tool konversi + backup + rollback (`--to-mvcc` / `--to-wal`) dengan peringatan eksplisit.
4. Retry/konflik tulis: definisi perilaku (retry otomatis vs error), audit write-skew pada counter/unique.
5. CI matrix: job default SQLite tetap wajib; job Turso terpisah dan boleh non-blocking.
6. Pin dependency: `turso = "=0.8.4"` (atau 0.9 saat stabil), cek MSRV 1.85, review build time & supply chain.
7. Keputusan risiko tertulis: MVCC beta, oracle tidak bisa buka MVCC `pb_data`, tidak ada multi-process.
8. Dokumentasi: dokumen ini, update `docs/COMPATIBILITY.md` dan `docs/UNKNOWNS.md`, pengecualian eksplisit pada tabel hard constraint di README.

---

## 7. Risiko utama

| Risiko | Dampak | Mitigasi |
|---|---|---|
| MVCC beta / bug engine | Korupsi atau perilaku tak terduga | Backup wajib sebelum flip; `integrity_check`; jangan jadikan default |
| Kehilangan drop-in | Oracle & tool SQLite tidak bisa buka data | Dokumentasikan sebagai mode eksklusif; sediakan `--to-wal` |
| Konflik tulis MVCC | 500/409 saat kontensi | Retry terpusat + uji beban konkuren |
| PRAGMA/DDL divergence | Gate M1–M8 gagal | Compatibility harness + gate per milestone |
| UI fork | Maintenance burden, L7 rusak | Jangan taruh di UI; pakai CLI/env |
| Churn dependency | Breaking change antar rilis | Pin exact; isolasi di balik feature |
| Crash recovery belum diuji | Kehilangan data | Tutup UNKNOWNS #8 (crash/fault-injection) sebelum produksi |

---

## 8. Keputusan

**DITUNDA.** Tidak ada perubahan kode. Dokumen ini menjadi bahan pertimbangan untuk lain waktu.

Saat akan dilanjutkan:
1. Pilih arah (F0+F1 / F2 / F3 / D).
2. Setujui rencana.
3. Setelah implementasi + build, pindahkan dokumen ini ke `docs/TURSO-MVCC.md` dan perbarui statusnya.

---

## 9. Referensi

- Turso COMPAT: `https://github.com/tursodatabase/turso/blob/main/COMPAT.md`
- Turso transactions (`BEGIN CONCURRENT`, `journal_mode=mvcc`): `https://docs.turso.tech/sql-reference/statements/transactions`
- Turso v0.4.0 (header MVCC, incompatibility dengan SQLite): `https://turso.tech/blog/turso-0.4.0`
- Turso v0.5.0 (MVCC beta): `https://turso.tech/blog/turso-0.5.0`
- Rust binding: `https://docs.rs/turso` / `https://github.com/tursodatabase/turso/tree/main/bindings/rust`
- Internal: `docs/PLAN.md`, `docs/COMPATIBILITY.md`, `docs/PERF-LIST-EXPAND.md`, `docs/UNKNOWNS.md`, `tools/load_wal.py`
