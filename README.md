# gatekeeper

Authum module: IP / ASN / country filtering and client identity for classic HLDS.

Heritage: AMXX plugins (`gatekeeper.core`, `gatekeeper.filter`, `gatekeeper.clients`,
`gatesql`) — IPHub lookup, SQL cache, whitelist, country/block kick, SteamID↔IP binding.

**Status:** Authum ABI 0.3 — SQLite/MySQL IP cache, IPHub lookup, country/block
filter, client steamid table, **steam_guard** (steamid↔ASN session antifraud).

## Build

SQL via Authum (`<authum/sql.h>`, SQLite inside Authum). IPHub uses plain HTTP sockets.
32-bit toolchain (`-m32` / i386) required — same as Authum / qproto modules.

```bash
git submodule update --init --recursive
cmake -S . -B build-linux32 -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux32 --target gatekeeper
# → build-linux32/modules/gatekeeper/gatekeeper.so
```

Debian/Ubuntu deps (once):

```bash
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install -y gcc-multilib g++-multilib cmake ninja-build \
  libc6-dev:i386 libstdc++-12-dev:i386
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
