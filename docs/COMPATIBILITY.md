# Compatibility contract

"Compatible" is defined narrowly and testably. Anything not listed here is not a
compatibility promise.

## Layers

| Layer | Requirement | Verified by |
|---|---|---|
| L1 CLI | `serve`, `superuser {create,update,upsert,delete,otp,ips}`, `migrate`, `version` accept the same flags and produce the same exit codes | scenario: CLI matrix |
| L2 On-disk | `pb_data/data.db` schema identical; `_migrations` rows identical; `_params.settings` JSON identical for a fresh install | `sqlite3 .schema` diff + row diff |
| L3 HTTP | 54 routes, same methods, same status codes, same JSON envelope `{code,message,data}` | harness `basic` + per-domain scenarios |
| L4 Auth | bcrypt hashes verify; JWT `HS256` with per-collection `authToken.secret`, claims `{collectionId,id,type,refreshable,exp}`; refresh, OTP, MFA, OAuth2, file tokens | cross-token test: token minted by oracle must validate in port and vice versa |
| L5 Query | filter/sort/expand/fields syntax and semantics, including NULL and relation traversal | differential fuzz of the filter parser |
| L6 Realtime | `text/event-stream` framing, `PB_CONNECT` event, subscription payloads | SSE scenario |
| L7 Static/UI | `/_/` serves the mirrored `ui/` tree with identical content types and SPA fallback | byte comparison of `ui/` |
| L8 JSVM | **not promised in v1** | — |

## Rules

1. **Normalization is explicit.** The harness replaces volatile values (record ids,
   timestamps, JWTs, 43-char secrets) with placeholders before comparing. A new
   normalization rule must be reviewed, because it can hide a real difference.
2. **JSON key order is not a contract.** Comparisons are semantic (parsed JSON).
3. **Error text is a contract.** The admin UI and SDKs surface `message` strings;
   they are compared verbatim.
4. **Response headers**: `content-type` is compared; the rest are recorded but not
   enforced in v1.
5. **Unknowns are recorded, not guessed.** When the oracle cannot be made to reveal
   behaviour (e.g. a code path requiring an external SMTP server), the gap is listed
   in `docs/UNKNOWNS.md` rather than filled with an assumption.

## Deliberate divergences

None yet. Any future divergence must be added here with its rationale and the
scenario that demonstrates it.
