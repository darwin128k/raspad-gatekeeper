# gatekeeper

Authum module: IP / ASN / country filtering and client identity for classic HLDS.

Heritage: AMXX plugins (`gatekeeper.core`, `gatekeeper.filter`, `gatekeeper.clients`,
`gatesql`) — IPHub lookup, SQL cache, whitelist, country/block kick, SteamID↔IP binding.

**Status:** Authum ABI 0.3 — SQLite/MySQL IP cache, IPHub lookup, country/block
filter, client steamid table, **steam_guard** (steamid↔ASN session antifraud).

## Build

SQL via Authum (`<authum/sql.h>`, SQLite inside Authum). IPHub uses plain HTTP sockets.

```bash
git submodule update --init --recursive
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target gatekeeper
```

Drop under `addons/authum/modules/gatekeeper/`:

- `gatekeeper.so`
- `gatekeeper.cfg`
- optional `gatekeeper.local.cfg` (API key — gitignored)
- optional `whitelist.ini`

Add `gatekeeper` to `modules.list`.

## Docs

- [docs/database.md](docs/database.md)
- [docs/amxx-heritage.md](docs/amxx-heritage.md)

## Related

- [Authum](https://github.com/darwin128k/raspad-authum) — host / events / commands
- [qproto](https://github.com/darwin128k/raspad-qproto) — non-Steam authorization
