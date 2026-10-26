# SQL setup (SQLite / MySQL)

Pick one driver in `gatekeeper.cfg` (or override in `gatekeeper.local.cfg`).  
Tables are created by an asynchronous startup task. Each player check opens a private connection; see [async.md](async.md).

Secrets (`sql_pass`, `iphub_api_key`) → `gatekeeper.local.cfg` next to `gatekeeper.so`.

---

## SQLite (default)

No server install. File lives under the module folder.

```ini
sql_driver = sqlite
sql_path = gatekeeper.sqlite
```

`sql_path` is relative to `addons/authum/modules/gatekeeper/` unless absolute.  
Ensure the `steam` (or HLDS) user can create/write that file.

That’s it.

---

## MySQL / MariaDB

Game module is **i386** — the host needs a **32-bit** client library even if the OS is amd64. MariaDB server itself can be 64-bit.

### 1. Server + i386 client (Debian / Ubuntu)

```bash
sudo apt update
sudo apt install -y mariadb-server

sudo dpkg --add-architecture i386
sudo apt update
sudo apt install -y libmariadb3:i386

sudo systemctl enable --now mariadb
```

(MySQL Server works the same if you prefer `mysql-server` + matching `libmysqlclient` i386.)

### 2. Database and user (localhost only)

```bash
sudo mysql <<'SQL'
CREATE DATABASE gatekeeper CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'gatekeeper'@'localhost' IDENTIFIED BY 'choose_a_strong_password';
GRANT ALL ON gatekeeper.* TO 'gatekeeper'@'localhost';
FLUSH PRIVILEGES;
SQL
```

### 3. Do not expose port 3306

```bash
# listen on loopback only
sudo sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' \
  /etc/mysql/mariadb.conf.d/50-server.cnf
sudo systemctl restart mariadb
ss -tlnp | grep 3306   # expect 127.0.0.1:3306
```

Do not `ufw allow 3306`. User `@'localhost'` already blocks remote logins.

### 4. Module cfg

`gatekeeper.cfg` or `gatekeeper.local.cfg`:

```ini
sql_driver = mysql
sql_host = 127.0.0.1
sql_port = 3306
sql_user = gatekeeper
sql_pass = choose_a_strong_password
sql_db = gatekeeper
```

Restart HLDS / reload the module. Check `SHOW TABLES;` in the DB after first connect — `user`, `client`, `session` should appear.

### 5. If MySQL open fails

- `libmariadb.so.3` missing for i386 → reinstall `libmariadb3:i386`
- wrong password / host → test:  
  `mysql -u gatekeeper -p -h 127.0.0.1 gatekeeper`
- Authum log under `modules/gatekeeper/` / `authum.log`

---

Schema details: [database.md](database.md).
