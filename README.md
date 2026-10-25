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

1. Download **`gatekeeper-linux32-authum.zip`** from [Releases](https://github.com/darwin128k/raspad-gatekeeper/releases) (or build below).
2. Unpack into the game dir so you get:
   - `addons/authum/modules/gatekeeper/gatekeeper.so`
   - `addons/authum/modules/gatekeeper/gatekeeper.cfg`
   - `addons/authum/modules/gatekeeper/whitelist.ini`
   - optional `gatekeeper.local.cfg` next to them (secrets — not in the zip)
3. Add `gatekeeper` to `addons/authum/modules.list`.
4. Pick SQL backend — see **[docs/sql-setup.md](docs/sql-setup.md)**  
   (SQLite out of the box, or MariaDB/MySQL + `libmariadb3:i386`).
5. Run Authum 4.0.0 (module ABI 1.0.0) — in Authum 4.0.0 Metamod is gone and
   Authum itself is the host image (`authum.so`), loaded where the game
   library used to be.

Defaults: steam_guard **learns** (`enforce=0`). Flip `steam_guard_enforce=1`
when you like the ASN history.

Sample keys: [`gatekeeper.cfg`](gatekeeper.cfg).

## Background checks

SQL, IPHub and whitelist lookups run in an Authum worker. Players enter first; a denied player is kicked when the result returns on a game frame. Results for disconnected players or old maps are discarded. Requires the updated Authum task API; see [docs/async.md](docs/async.md).

## SQL schema

Created automatically on module start (`CREATE TABLE IF NOT EXISTS`).  
Default names — override with `sql_table_ip` / `sql_table_client` / `sql_table_session`.

| Cfg key | Default | Purpose |
|---------|---------|---------|
| `sql_table_ip` | `user` | IPHub cache: one row per IP |
| `sql_table_client` | `client` | SteamID → last known IP row (`logid`) |
| `sql_table_session` | `session` | steam_guard: SteamID ↔ ASN history |

**`user` (IP cache)**

| Column | Meaning |
|--------|---------|
| `id` | PK |
| `asn` | ASN number |
| `ip` | IP (unique) |
| `code` | country code (`RU`, …) |
| `name` | country name |
| `isp` | ISP string |
| `block` | IPHub block score |

**`client`**

| Column | Meaning |
|--------|---------|
| `id` | PK |
| `logid` | FK → `user.id` |
| `steamid` | Steam / Valve id (unique) |

**`session` (steam_guard)**

| Column | Meaning |
|--------|---------|
| `id` | PK |
| `steamid` | player id |
| `logid` | FK → `user.id` (last IP row for this ASN) |
| `asn` | ASN (unique together with steamid) |
| `code` | country at that ASN |
| `hits` | how many times seen |

Drivers: `sql_driver=sqlite` (file `sql_path`) or `mysql` (`sql_host` / `user` / `pass` / `db` / `port`).  
How to install either backend: [docs/sql-setup.md](docs/sql-setup.md).  
Full `CREATE TABLE`: [docs/database.md](docs/database.md).

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
sudo apt-get install -y gcc-multilib cmake ninja-build \
  libc6-dev:i386
```

## Docs

- [docs/sql-setup.md](docs/sql-setup.md) — install SQLite or MySQL/MariaDB
- [docs/database.md](docs/database.md) — tables / DDL

## Related

- [Authum](https://github.com/darwin128k/raspad-authum) — module host  
- [qproto](https://github.com/darwin128k/raspad-qproto) — non-Steam authorization
