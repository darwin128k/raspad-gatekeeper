#include <gatekeeper/sql.h>

#include <gatekeeper/config.h>
#include <gatekeeper/host.h>

#include <authum/cstr.h>
#include <authum/host.h>
#include <authum/null.h>
#include <authum/path.h>
#include <authum/sql.h>

#include <stdio.h>

#if defined(_WIN32)
#    include <windows.h>
#else
#    include <unistd.h>
#endif

static _Thread_local authum_sql_t *g_db;
static _Thread_local authum_char_t g_sql_error[authum_sql_errmsg_max];

void
gatekeeper_sql_bind(authum_sql_t *db)
{
    g_db = db;
    g_sql_error[0] = '\0';
}
const authum_char_t *
gatekeeper_sql_error(void)
{
    return g_sql_error;
}
void
gatekeeper_sql_record_error(void)
{
    if (g_db && !g_sql_error[0] && authum_sql_errmsg(g_db)[0])
    {
        snprintf(g_sql_error, sizeof g_sql_error, "%s", authum_sql_errmsg(g_db));
    }
}
authum_bool_t
gatekeeper_sql_prepare(authum_sql_t *db, authum_sql_stmt_t *stmt, const authum_char_t *sql)
{
    authum_bool_t ok = authum_sql_prepare(db, stmt, sql);
    if (!ok)
    {
        gatekeeper_sql_record_error();
    }
    return ok;
}
authum_bool_t
gatekeeper_sql_step_row(authum_sql_stmt_t *stmt)
{
    authum_bool_t ok = authum_sql_stmt_step_row(stmt);
    if (!ok)
    {
        gatekeeper_sql_record_error();
    }
    return ok;
}
authum_bool_t
gatekeeper_sql_step_done(authum_sql_stmt_t *stmt)
{
    authum_bool_t ok = authum_sql_stmt_step_done(stmt);
    if (!ok)
    {
        gatekeeper_sql_record_error();
    }
    return ok;
}

authum_bool_t
gatekeeper_sql_ensure_schema(void)
{
    authum_char_t sql[640];

    if (g_db->driver == authum_sql_driver_mysql)
    {
        snprintf(sql, sizeof sql,
                 "CREATE TABLE IF NOT EXISTS `%s` ("
                 "`id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
                 "`asn` INT NOT NULL,"
                 "`ip` VARCHAR(45) NOT NULL,"
                 "`code` VARCHAR(8),"
                 "`name` VARCHAR(128),"
                 "`isp` VARCHAR(256),"
                 "`block` INT NOT NULL,"
                 "UNIQUE KEY `uk_ip` (`ip`)"
                 ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
                 g_gatekeeper_config.sql_table_ip);
    }
    else
    {
        snprintf(sql, sizeof sql,
                 "CREATE TABLE IF NOT EXISTS `%s` ("
                 "`id` INTEGER PRIMARY KEY AUTOINCREMENT,"
                 "`asn` INTEGER NOT NULL,"
                 "`ip` TEXT NOT NULL UNIQUE,"
                 "`code` TEXT,"
                 "`name` TEXT,"
                 "`isp` TEXT,"
                 "`block` INTEGER NOT NULL"
                 ");",
                 g_gatekeeper_config.sql_table_ip);
    }
    if (!authum_sql_exec(g_db, sql))
    {
        authum_logger_error(gatekeeper_log(), "sql schema ip: %s", authum_sql_errmsg(g_db));
        return authum_bool_false;
    }

    if (g_db->driver == authum_sql_driver_mysql)
    {
        snprintf(sql, sizeof sql,
                 "CREATE TABLE IF NOT EXISTS `%s` ("
                 "`id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
                 "`logid` INT NOT NULL,"
                 "`steamid` VARCHAR(64) NOT NULL,"
                 "UNIQUE KEY `uk_steamid` (`steamid`)"
                 ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
                 g_gatekeeper_config.sql_table_client);
    }
    else
    {
        snprintf(sql, sizeof sql,
                 "CREATE TABLE IF NOT EXISTS `%s` ("
                 "`id` INTEGER PRIMARY KEY AUTOINCREMENT,"
                 "`logid` INTEGER NOT NULL,"
                 "`steamid` TEXT NOT NULL UNIQUE"
                 ");",
                 g_gatekeeper_config.sql_table_client);
    }
    if (!authum_sql_exec(g_db, sql))
    {
        authum_logger_error(gatekeeper_log(), "sql schema client: %s", authum_sql_errmsg(g_db));
        return authum_bool_false;
    }

    /* steamid ↔ ASN sessions (stolen-ticket / shared-account budget). */
    if (g_db->driver == authum_sql_driver_mysql)
    {
        snprintf(sql, sizeof sql,
                 "CREATE TABLE IF NOT EXISTS `%s` ("
                 "`id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
                 "`steamid` VARCHAR(64) NOT NULL,"
                 "`logid` INT NOT NULL,"
                 "`asn` INT NOT NULL,"
                 "`code` VARCHAR(8),"
                 "`hits` INT NOT NULL DEFAULT 1,"
                 "UNIQUE KEY `uk_steam_asn` (`steamid`,`asn`)"
                 ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
                 g_gatekeeper_config.sql_table_session);
    }
    else
    {
        snprintf(sql, sizeof sql,
                 "CREATE TABLE IF NOT EXISTS `%s` ("
                 "`id` INTEGER PRIMARY KEY AUTOINCREMENT,"
                 "`steamid` TEXT NOT NULL,"
                 "`logid` INTEGER NOT NULL,"
                 "`asn` INTEGER NOT NULL,"
                 "`code` TEXT,"
                 "`hits` INTEGER NOT NULL DEFAULT 1,"
                 "UNIQUE(`steamid`,`asn`)"
                 ");",
                 g_gatekeeper_config.sql_table_session);
    }
    if (!authum_sql_exec(g_db, sql))
    {
        authum_logger_error(gatekeeper_log(), "sql schema session: %s", authum_sql_errmsg(g_db));
        return authum_bool_false;
    }
    return authum_bool_true;
}

authum_bool_t
gatekeeper_sql_get_by_ip(const authum_char_t *ip, gatekeeper_iphub_data_t *out)
{
    authum_char_t sql[256];
    authum_sql_stmt_t stmt;

    if (!authum_sql_is_open(g_db) || authum_null_eq(ip) || authum_null_eq(out))
    {
        return authum_bool_false;
    }

    gatekeeper_iphub_data_clear(out);
    snprintf(sql, sizeof sql, "SELECT id,asn,ip,code,name,isp,block FROM `%s` WHERE ip=? LIMIT 1",
             g_gatekeeper_config.sql_table_ip);
    if (!gatekeeper_sql_prepare(g_db, &stmt, sql))
    {
        return authum_bool_false;
    }

    authum_sql_stmt_bind_cstr(&stmt, 1, ip);
    if (gatekeeper_sql_step_row(&stmt))
    {
        out->id = authum_sql_stmt_column_i32(&stmt, 0);
        out->asn = authum_sql_stmt_column_i32(&stmt, 1);
        authum_cstr_copy(out->ip, sizeof out->ip, authum_sql_stmt_column_cstr(&stmt, 2));
        authum_cstr_copy(out->code, sizeof out->code, authum_sql_stmt_column_cstr(&stmt, 3));
        authum_cstr_copy(out->name, sizeof out->name, authum_sql_stmt_column_cstr(&stmt, 4));
        authum_cstr_copy(out->isp, sizeof out->isp, authum_sql_stmt_column_cstr(&stmt, 5));
        out->block = authum_sql_stmt_column_i32(&stmt, 6);
        authum_sql_stmt_finalize(&stmt);
        return authum_bool_true;
    }
    authum_sql_stmt_finalize(&stmt);
    return authum_bool_false;
}

authum_bool_t
gatekeeper_sql_insert_ip(gatekeeper_iphub_data_t *row)
{
    authum_char_t sql[256];
    authum_sql_stmt_t stmt;

    if (!authum_sql_is_open(g_db) || authum_null_eq(row))
    {
        return authum_bool_false;
    }

    snprintf(sql, sizeof sql, "INSERT INTO `%s` (asn,ip,code,name,isp,block) VALUES (?,?,?,?,?,?)",
             g_gatekeeper_config.sql_table_ip);
    if (!gatekeeper_sql_prepare(g_db, &stmt, sql))
    {
        return authum_bool_false;
    }

    authum_sql_stmt_bind_i32(&stmt, 1, row->asn);
    authum_sql_stmt_bind_cstr(&stmt, 2, row->ip);
    authum_sql_stmt_bind_cstr(&stmt, 3, row->code);
    authum_sql_stmt_bind_cstr(&stmt, 4, row->name);
    authum_sql_stmt_bind_cstr(&stmt, 5, row->isp);
    authum_sql_stmt_bind_i32(&stmt, 6, row->block);

    if (!gatekeeper_sql_step_done(&stmt))
    {
        authum_logger_error(gatekeeper_log(), "sql insert ip: %s", authum_sql_errmsg(g_db));
        authum_sql_stmt_finalize(&stmt);
        return authum_bool_false;
    }
    row->id = (authum_i32_t)authum_sql_last_insert_id(g_db);
    authum_sql_stmt_finalize(&stmt);
    return authum_bool_true;
}

authum_i32_t
gatekeeper_sql_ensure_client(authum_i32_t log_id, const authum_char_t *steamid)
{
    authum_char_t sql[256];
    authum_sql_stmt_t stmt;
    authum_i32_t id = -1;

    if (!authum_sql_is_open(g_db) || authum_null_eq(steamid) || steamid[0] == '\0' || log_id < 0)
    {
        return -1;
    }

    snprintf(sql, sizeof sql, "SELECT id FROM `%s` WHERE steamid=? LIMIT 1",
             g_gatekeeper_config.sql_table_client);
    if (!gatekeeper_sql_prepare(g_db, &stmt, sql))
    {
        return -1;
    }
    authum_sql_stmt_bind_cstr(&stmt, 1, steamid);
    if (gatekeeper_sql_step_row(&stmt))
    {
        id = authum_sql_stmt_column_i32(&stmt, 0);
    }
    authum_sql_stmt_finalize(&stmt);
    if (id >= 0)
    {
        return id;
    }

    snprintf(sql, sizeof sql, "INSERT INTO `%s` (logid,steamid) VALUES (?,?)",
             g_gatekeeper_config.sql_table_client);
    if (!gatekeeper_sql_prepare(g_db, &stmt, sql))
    {
        return -1;
    }
    authum_sql_stmt_bind_i32(&stmt, 1, log_id);
    authum_sql_stmt_bind_cstr(&stmt, 2, steamid);
    if (!gatekeeper_sql_step_done(&stmt))
    {
        authum_sql_stmt_finalize(&stmt);
        return -1;
    }
    id = (authum_i32_t)authum_sql_last_insert_id(g_db);
    authum_sql_stmt_finalize(&stmt);
    return id;
}

authum_bool_t
gatekeeper_sql_session_has_asn(const authum_char_t *steamid, authum_i32_t asn)
{
    authum_char_t sql[256];
    authum_sql_stmt_t stmt;
    authum_bool_t hit = authum_bool_false;

    if (!authum_sql_is_open(g_db) || authum_null_eq(steamid) || steamid[0] == '\0')
    {
        return authum_bool_false;
    }
    snprintf(sql, sizeof sql, "SELECT id FROM `%s` WHERE steamid=? AND asn=? LIMIT 1",
             g_gatekeeper_config.sql_table_session);
    if (!gatekeeper_sql_prepare(g_db, &stmt, sql))
    {
        return authum_bool_false;
    }
    authum_sql_stmt_bind_cstr(&stmt, 1, steamid);
    authum_sql_stmt_bind_i32(&stmt, 2, asn);
    if (gatekeeper_sql_step_row(&stmt))
    {
        hit = authum_bool_true;
    }
    authum_sql_stmt_finalize(&stmt);
    return hit;
}

authum_bool_t
gatekeeper_sql_session_has_code(const authum_char_t *steamid, const authum_char_t *code)
{
    authum_char_t sql[256];
    authum_sql_stmt_t stmt;
    authum_bool_t hit = authum_bool_false;

    if (!authum_sql_is_open(g_db) || authum_null_eq(steamid) || steamid[0] == '\0' ||
        authum_null_eq(code) || code[0] == '\0')
    {
        return authum_bool_false;
    }
    snprintf(sql, sizeof sql, "SELECT id FROM `%s` WHERE steamid=? AND code=? LIMIT 1",
             g_gatekeeper_config.sql_table_session);
    if (!gatekeeper_sql_prepare(g_db, &stmt, sql))
    {
        return authum_bool_false;
    }
    authum_sql_stmt_bind_cstr(&stmt, 1, steamid);
    authum_sql_stmt_bind_cstr(&stmt, 2, code);
    if (gatekeeper_sql_step_row(&stmt))
    {
        hit = authum_bool_true;
    }
    authum_sql_stmt_finalize(&stmt);
    return hit;
}

authum_i32_t
gatekeeper_sql_session_asn_count(const authum_char_t *steamid)
{
    authum_char_t sql[256];
    authum_sql_stmt_t stmt;
    authum_i32_t n = 0;

    if (!authum_sql_is_open(g_db) || authum_null_eq(steamid) || steamid[0] == '\0')
    {
        return 0;
    }
    snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM `%s` WHERE steamid=?",
             g_gatekeeper_config.sql_table_session);
    if (!gatekeeper_sql_prepare(g_db, &stmt, sql))
    {
        return 0;
    }
    authum_sql_stmt_bind_cstr(&stmt, 1, steamid);
    if (gatekeeper_sql_step_row(&stmt))
    {
        n = authum_sql_stmt_column_i32(&stmt, 0);
    }
    authum_sql_stmt_finalize(&stmt);
    return n;
}

authum_bool_t
gatekeeper_sql_session_touch(const authum_char_t *steamid, const gatekeeper_iphub_data_t *data)
{
    authum_char_t sql[320];
    authum_sql_stmt_t stmt;

    if (!authum_sql_is_open(g_db) || authum_null_eq(steamid) || authum_null_eq(data) ||
        data->id < 0)
    {
        return authum_bool_false;
    }

    if (gatekeeper_sql_session_has_asn(steamid, data->asn))
    {
        snprintf(sql, sizeof sql,
                 "UPDATE `%s` SET hits=hits+1, logid=?, code=? WHERE steamid=? AND asn=?",
                 g_gatekeeper_config.sql_table_session);
        if (!gatekeeper_sql_prepare(g_db, &stmt, sql))
        {
            return authum_bool_false;
        }
        authum_sql_stmt_bind_i32(&stmt, 1, data->id);
        authum_sql_stmt_bind_cstr(&stmt, 2, data->code);
        authum_sql_stmt_bind_cstr(&stmt, 3, steamid);
        authum_sql_stmt_bind_i32(&stmt, 4, data->asn);
        if (!gatekeeper_sql_step_done(&stmt))
        {
            authum_sql_stmt_finalize(&stmt);
            return authum_bool_false;
        }
        authum_sql_stmt_finalize(&stmt);
        return authum_bool_true;
    }

    snprintf(sql, sizeof sql, "INSERT INTO `%s` (steamid,logid,asn,code,hits) VALUES (?,?,?,?,1)",
             g_gatekeeper_config.sql_table_session);
    if (!gatekeeper_sql_prepare(g_db, &stmt, sql))
    {
        return authum_bool_false;
    }
    authum_sql_stmt_bind_cstr(&stmt, 1, steamid);
    authum_sql_stmt_bind_i32(&stmt, 2, data->id);
    authum_sql_stmt_bind_i32(&stmt, 3, data->asn);
    authum_sql_stmt_bind_cstr(&stmt, 4, data->code);
    if (!gatekeeper_sql_step_done(&stmt))
    {
        authum_logger_error(gatekeeper_log(), "sql session insert: %s", authum_sql_errmsg(g_db));
        authum_sql_stmt_finalize(&stmt);
        return authum_bool_false;
    }
    authum_sql_stmt_finalize(&stmt);
    return authum_bool_true;
}
