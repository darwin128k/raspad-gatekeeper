# Database

Schema is owned by gatekeeper; Authum only provides the engine
(`<authum/sql.h>` — SQLite linked, MySQL via `dlopen`).

Tables are created on start. Names come from cfg (defaults below).

## Drivers

| `sql_driver` | Settings |
|--------------|----------|
| `sqlite` | `sql_path` under the module directory (default `gatekeeper.sqlite`) |
| `mysql` | `sql_host`, `sql_user`, `sql_pass`, `sql_db`, `sql_port` (0 → 3306) |

Install / host packages / localhost lockdown: [sql-setup.md](sql-setup.md).

## Tables (defaults)

| Cfg | Default | Role |
|-----|---------|------|
| `sql_table_ip` | `user` | IPHub / geo cache |
| `sql_table_client` | `client` | SteamID ↔ IP row |
| `sql_table_session` | `session` | steam_guard ASN budget |

Flow: IP lookup in `user` → miss → IPHub → INSERT → filter → steam_guard
touches `session` → ensure row in `client`.

---

### `user` — IP cache

| Column | Type (idea) | Notes |
|--------|-------------|-------|
| `id` | integer PK | autoincrement |
| `asn` | int | |
| `ip` | string | **unique** |
| `code` | string | country code |
| `name` | string | country name |
| `isp` | string | |
| `block` | int | IPHub block |

SQLite:

```sql
CREATE TABLE IF NOT EXISTS `user` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `asn` INTEGER NOT NULL,
  `ip` TEXT NOT NULL UNIQUE,
  `code` TEXT,
  `name` TEXT,
  `isp` TEXT,
  `block` INTEGER NOT NULL
);
```

MySQL:

```sql
CREATE TABLE IF NOT EXISTS `user` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `asn` INT NOT NULL,
  `ip` VARCHAR(45) NOT NULL,
  `code` VARCHAR(8),
  `name` VARCHAR(128),
  `isp` VARCHAR(256),
  `block` INT NOT NULL,
  UNIQUE KEY `uk_ip` (`ip`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

---

### `client` — SteamID binding

| Column | Notes |
|--------|--------|
| `id` | PK |
| `logid` | → `user.id` |
| `steamid` | unique |

SQLite:

```sql
CREATE TABLE IF NOT EXISTS `client` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `logid` INTEGER NOT NULL,
  `steamid` TEXT NOT NULL UNIQUE
);
```

MySQL:

```sql
CREATE TABLE IF NOT EXISTS `client` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `logid` INT NOT NULL,
  `steamid` VARCHAR(64) NOT NULL,
  UNIQUE KEY `uk_steamid` (`steamid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

---

### `session` — steam_guard

| Column | Notes |
|--------|--------|
| `id` | PK |
| `steamid` | |
| `logid` | → `user.id` |
| `asn` | unique with steamid |
| `code` | country for that ASN |
| `hits` | counter |

SQLite:

```sql
CREATE TABLE IF NOT EXISTS `session` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `steamid` TEXT NOT NULL,
  `logid` INTEGER NOT NULL,
  `asn` INTEGER NOT NULL,
  `code` TEXT,
  `hits` INTEGER NOT NULL DEFAULT 1,
  UNIQUE(`steamid`,`asn`)
);
```

MySQL:

```sql
CREATE TABLE IF NOT EXISTS `session` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `steamid` VARCHAR(64) NOT NULL,
  `logid` INT NOT NULL,
  `asn` INT NOT NULL,
  `code` VARCHAR(8),
  `hits` INT NOT NULL DEFAULT 1,
  UNIQUE KEY `uk_steam_asn` (`steamid`,`asn`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```
