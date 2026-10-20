# Database

Gatekeeper owns its own SQL — not Authum.

## Drivers

| `SqlDriver` | Status |
|-------------|--------|
| `sqlite` | **Default.** File under module dir (`SqlPath`, default `gatekeeper.sqlite`). |
| `mysql` | Reserved in cfg (`SqlHost` / `SqlUser` / …). Not linked yet — same schema later. |

## Tables (AMXX-compatible names)

**`SqlTableIp` (default `user`)**

| Column | Meaning |
|--------|---------|
| id | row id |
| asn | ASN |
| ip | unique |
| code | country code |
| name | country name |
| isp | ISP |
| block | IPHub block level |

**`SqlTableClient` (default `client`)**

| Column | Meaning |
|--------|---------|
| id | row id |
| logid | FK → ip row id |
| steamid | unique auth id |

Resolve path: lookup IP → on miss IPHub → INSERT → optional client row on auth id.
