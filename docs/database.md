# Database

Gatekeeper owns **schema and queries**. The SQL **engine** is Authum’s brick
`<authum/sql.h>` (SQLite linked; MySQL via dlopen on the host).

## Drivers (`gatekeeper.cfg` → Authum)

| `sql_driver` | Status |
|--------------|--------|
| `sqlite` | Default. File under module dir (`sql_path`). |
| `mysql` | `sql_host` / `sql_user` / `sql_pass` / `sql_db` / `sql_port`. |

## Tables

**`sql_table_ip` (default `user`)** — asn, ip, code, name, isp, block  

**`sql_table_client` (default `client`)** — logid, steamid  

**`sql_table_session` (default `session`)** — steamid, logid, asn, code, hits  
Steam-session antifraud: distinct ASNs (and optional country) per steamid.

Resolve: lookup IP → miss → IPHub → INSERT → country/block filter → steam_guard →
optional client row on auth id.
