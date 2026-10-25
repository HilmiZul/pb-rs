# Unknowns

Behaviour the oracle could not be made to reveal in the current environment, or that
is out of scope for v1. These are gaps in evidence, not assumptions.

| # | Unknown | Why it is open | How to close it |
|---|---|---|---|
| 1 | SMTP delivery, templates, retry behaviour | no mail server; `smtp.enabled=false` in the seed | run a local sink (MailHog) and record |
| 2 | S3 storage backend semantics | requires an S3-compatible endpoint | run MinIO, record |
| 3 | OAuth2 provider flows end-to-end | requires real provider credentials | mock the token endpoint and record |
| 4 | Realtime SSE framing over long sessions | the current harness reads whole bodies; SSE never terminates | add a streaming recorder (M5) |
| 5 | `update` command behaviour | it would fetch and replace the executable | sandbox + local HTTP server replay |
| 6 | Thumbnail generation byte output | depends on Go's image encoders; exact bytes may differ by codec | compare dimensions/format only, or accept divergence |
| 7 | JSVM hook semantics | goja is out of scope for v1 | M6 |
| 8 | Behaviour under concurrent writes / WAL contention | needs load + fault injection | M7 |
| 9 | Rate-limiter timing boundaries | wall-clock dependent | injectable clock in the port, record with the oracle |

## Known-bounded negative results

- The 4 routes in `spec/routes-verified.tsv` marked `exists=NO` are **not** missing
  routes: they return 404 because the probed record id does not exist
  (`/records/{id}`, `/files/{collection}/{recordId}/{filename}`). This is a bounded
  observation, not proof about other record ids.
