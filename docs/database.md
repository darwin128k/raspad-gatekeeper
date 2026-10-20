# Database

Gatekeeper owns **schema and queries**. The SQL **engine** is Authum’s brick
[`<authum/sql.h>`](../lib/authum/docs/sql.md) (SQLite under Authum `lib/sqlite`).

## Drivers (`gatekeeper.cfg` → Authum)

| `SqlDriver` | Status |
|-------------|--------|
| `sqlite` | Default. File under module dir (`SqlPath`). |
| `mysql` | Reserved in Authum enum — not linked yet. |

## Tables (AMXX-compatible names)

**`SqlTableIp` (default `user`)** — asn, ip, code, name, isp, block  

**`SqlTableClient` (default `client`)** — logid, steamid  

Resolve: lookup IP → miss → IPHub → INSERT → optional client row on auth id.
