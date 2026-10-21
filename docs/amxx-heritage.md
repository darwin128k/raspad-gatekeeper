# AMXX Gatekeeper → Authum map

Source: Desktop `raspad/Pawn/*.sma`. The old stack was several plugins; Authum
gatekeeper is **one module** that owns the same jobs end-to-end.

| AMXX plugin | Role | In Authum gatekeeper |
|-------------|------|----------------------|
| `gatekeeper.sma` / early collector | IPHub + SQL IP → asn/code/isp/block | `sql` + `iphub` + resolve |
| `gatekeeper.core.sma` | SQL / IPHub / forwards | resolve + `gatekeeper.client.resolved` |
| `gatekeeper.filter.sma` | country / block / whitelist kick | `filter_*` |
| `gatekeeper.clients.sma` | steamid ↔ logid (IP row) | `sql_table_client` |
| `gatesql.sma` | name↔IP↔SteamID binder (ReAPI) | sibling idea; not ported as ReAPI |
| (forum / wishlist) | stolen Steam ticket policy | `steam_guard_*` + `sql_table_session` |

## Data flow (now)

1. `authum.client.connect` → strip IP → SQL lookup → miss → IPHub → INSERT.
2. Country / block filter (+ `whitelist.ini`).
3. `steam_guard`: touch or deny ASN/country budget for this SteamID.
4. Ensure client row; publish `gatekeeper.client.resolved`.
5. On put-in-server: re-check filter + steam_guard (kick if needed).

No separate “core vs filter” plugins, no AMXX natives — policy lives in this
repo; engines live in Authum bricks.
