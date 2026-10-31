# Gatekeeper: shared mechanisms and module policy

The reusable mechanisms now live in Authum's
[shared-services API](../lib/authum/docs/shared-services.md):

| Extracted mechanism | API | Other users |
|---|---|---|
| Worker log capture / game-thread delivery | `authum_logger_buffer_*` | any module doing background work |
| Stable player-connection identity | `authum_clients_*`, `authum_client_ref_is_current` | bans, stats, profiles, inventory, asynchronous authorizations |
| First SQL error retained across a batch | `authum_sql_first_error`, `authum_sql_clear_errors` | every SQL module, including threaded queries |
| Host extraction from an address | `authum_net_address_copy_host` | network filters, monitoring, query/ticket modules |

Gatekeeper no longer implements its own worker logger, generation array or
prepare/step wrappers. Per-slot copies of userid, auth id, SQL client id and the
IPHub response were also unused after background checks; they are removed.
Each slot now keeps only the connection IP and used/pending flags. Query results
remain in the job and are published through the same resolved event.

## What remains gatekeeper's responsibility

- IPHub-specific JSON fields and cache records.
- Geo/proxy policy, ASN limits and the action taken on a database error.
- Whitelist flags and matching rules.
- Database schema, table names, queries and domain writes.
- The resolved event and delayed-kick decision.

Moving these into Authum would couple the host to one module's policy.

## Next useful extractions

1. HTTP transport, separately from IPHub JSON parsing: partial I/O, bounded
   responses, content length/chunking, deadlines, TLS and dependency policy need
   dedicated tests before promising a reusable HTTP client.
2. A host-owned SQL backend if binary size is a goal. `authum_client` currently
   links lh/SQLite statically into modules; moving helper source files into the
   client library reduces duplicated source and responsibility, but does not
   remove SQLite from gatekeeper.so. A host SQL ops table would allow thin
   wrappers and one backend implementation, with explicit compatibility,
   worker/thread lifetime and allocator-ownership tests. JSON can follow the
   same model if useful.

This change introduces no new runtime dependencies or changes to the SQL schema,
filter configuration or resolved-event layout. Synchronous last-error behavior
is preserved; threaded batches now also reject an unacknowledged first failure.
An intentional SQL fallback must call `authum_sql_clear_errors`.
