<p align="center">
  <img src="assets/logo.png" alt="gatekeeper" width="220">
</p>

<h1 align="center">gatekeeper</h1>

<p align="center">
  <b>Authum module</b> for classic HLDS<br>
  Geo / proxy filter + Steam session guard — who gets in stays yours.
</p>

<p align="center">
  <a href="LICENSE">Apache-2.0</a> ·
  <a href="https://github.com/darwin128k/raspad-gatekeeper">GitHub</a> ·
  <a href="https://github.com/darwin128k/raspad-authum">Authum</a>
</p>

---

## Why install it

Your server is public. Half the grief is **bad networks** (VPN, hosting, wrong
country) and **borrowed Steam accounts** (same SteamID, new ASN overnight).

gatekeeper sits on Authum and, on every connect:

- looks up the IP (cache in SQL, live via IPHub when unknown);
- kicks by country list and IPHub block score — or skips via whitelist;
- remembers which ASNs that SteamID already used (**steam_guard**);
- optionally rejects when the session jumps too far (stolen / shared tickets).

Works with **SQLite** (zero ops) or **MySQL/MariaDB**. One `.so`, one cfg.
Pairs cleanly with [qproto](https://github.com/darwin128k/raspad-qproto) for
non-Steam auth — qproto answers *how* they logged in; gatekeeper answers
*whether that login still looks sane*.

## Features

| | |
|--|--|
| IPHub geo + proxy/block score | cached in SQL |
| Country allow / deny list | `filter_countries` |
| Whitelist | ASN / IP / SteamID / block flags |
| Steam session antifraud | ASN (+ optional country) budget per SteamID |
| SQLite or MySQL | Authum SQL brick (`dlopen` for MySQL) |
| Event for other modules | `gatekeeper.client.resolved` |

Secrets (IPHub key, SQL password) go in `gatekeeper.local.cfg` — never commit them.

## Install

1. Take `gatekeeper.so` from [Releases](https://github.com/darwin128k/raspad-gatekeeper/releases) or build below.
2. Put under `addons/authum/modules/gatekeeper/`:
   - `gatekeeper.so`
   - `gatekeeper.cfg`
   - optional `gatekeeper.local.cfg`, `whitelist.ini`
3. Add `gatekeeper` to `addons/authum/modules.list`.
4. Run Authum (ABI 0.3) under Metamod.

MySQL on the game host needs an **i386** client library (`libmariadb3:i386`) —
the module loads it at runtime.

Defaults: steam_guard **learns** (`enforce=0`). Flip `steam_guard_enforce=1`
when you like the ASN history.

Sample keys: [`gatekeeper.cfg`](gatekeeper.cfg).

## Build

Linux i386 (`-m32`), same as other Authum modules.

```bash
git submodule update --init --recursive
cmake -S . -B build-linux32 -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux32 --target gatekeeper
# → build-linux32/modules/gatekeeper/gatekeeper.so
```

```bash
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install -y gcc-multilib g++-multilib cmake ninja-build \
  libc6-dev:i386 libstdc++-12-dev:i386
```

## Docs

- [docs/database.md](docs/database.md) — tables / drivers

## Related

- [Authum](https://github.com/darwin128k/raspad-authum) — module host  
- [qproto](https://github.com/darwin128k/raspad-qproto) — non-Steam authorization
