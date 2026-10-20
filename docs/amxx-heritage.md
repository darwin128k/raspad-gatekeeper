# AMXX Gatekeeper → Authum map (reference)

Source: Desktop `raspad/Pawn/*.sma`. Core path ported (SQLite + IPHub + filter + client table).

| AMXX plugin | Role |
|-------------|------|
| `gatekeeper.sma` / early collector | IPHub + SQL table of IP → asn/code/isp/block |
| `gatekeeper.core.sma` | Core: SQL tuple natives, IPHub request, forward `gatekeeper_client_authorized` / registered |
| `gatekeeper.filter.sma` | Kick on country deny / IPHub `block` vs cvar; `whitelist.ini` (ASN/IP/SteamID/block flags) |
| `gatekeeper.clients.sma` | SQL `client` table: steamid ↔ logid (IP row) |
| `gatesql.sma` | Separate name↔IP↔SteamID binder (ReAPI hooks); sibling idea, not the same plugin tree |

## Data flow (core + filter)

1. `client_authorized` → lookup IP in SQL; miss → IPHub API.
2. On IPHub OK → INSERT row → forward to listeners.
3. Filter listens → whitelist skip → else country list + `block` threshold → `kick #userid`.

## Authum shape (planned)

- One module `gatekeeper` (or core + filter as events later).
- Subscribe `authum.client.*` / qproto authorized when present.
- Config: `gatekeeper.cfg` via `authum_cfg_*`.
- SQL + HTTP IPHub as bricks; kick via `authum_host_kick`.
- Whitelist file under module dir.

Stolen Steam tickets are **out of scope** for the IPHub filter; that is a separate Steam-session policy (mentioned on the forums as future work in this product line).
