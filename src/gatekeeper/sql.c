#include <gatekeeper/sql.h>

#include <gatekeeper/config.h>
#include <gatekeeper/host.h>

#include <authum/cstr.h>
#include <authum/host.h>
#include <authum/null.h>
#include <authum/path.h>

#include <stdio.h>
#include <string.h>

#include <sqlite3.h> /* third_party/sqlite */

static sqlite3 *g_db;

static authum_bool_t
gatekeeper_sql_exec(const authum_char_t *sql)
{
	authum_char_t *err = authum_null;
	int rc;

	if (authum_null_eq(g_db))
		return authum_bool_false;
	rc = sqlite3_exec(g_db, sql, authum_null, authum_null, &err);
	if (rc != SQLITE_OK) {
		authum_logger_error(&g_gatekeeper_logger, "sql: %s", err ? err : "error");
		sqlite3_free(err);
		return authum_bool_false;
	}
	return authum_bool_true;
}

static authum_bool_t
gatekeeper_sql_ensure_schema(void)
{
	authum_char_t sql[512];

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
	if (!gatekeeper_sql_exec(sql))
		return authum_bool_false;

	snprintf(sql, sizeof sql,
		 "CREATE TABLE IF NOT EXISTS `%s` ("
		 "`id` INTEGER PRIMARY KEY AUTOINCREMENT,"
		 "`logid` INTEGER NOT NULL,"
		 "`steamid` TEXT NOT NULL UNIQUE"
		 ");",
		 g_gatekeeper_config.sql_table_client);
	return gatekeeper_sql_exec(sql);
}

authum_bool_t
gatekeeper_sql_open(void)
{
	authum_path_t path;
	int rc;

	if (g_gatekeeper_config.sql_driver == gatekeeper_sql_driver_mysql) {
		authum_logger_error(&g_gatekeeper_logger,
				    "SqlDriver=mysql not built yet — use sqlite (SqlPath)");
		return authum_bool_false;
	}

	if (!authum_path_join(&path, authum_host_env_module(&g_gatekeeper_host),
			      g_gatekeeper_config.sql_path)) {
		authum_logger_error(&g_gatekeeper_logger, "sql: bad path");
		return authum_bool_false;
	}

	rc = sqlite3_open(authum_path_as_cstr(&path), &g_db);
	if (rc != SQLITE_OK) {
		authum_logger_error(&g_gatekeeper_logger, "sqlite open FAILED: %s (%s)",
				    g_db ? sqlite3_errmsg(g_db) : "?", authum_path_as_cstr(&path));
		if (!authum_null_eq(g_db)) {
			sqlite3_close(g_db);
			g_db = authum_null;
		}
		return authum_bool_false;
	}

	authum_logger_info(&g_gatekeeper_logger, "sqlite open: %s", authum_path_as_cstr(&path));
	return gatekeeper_sql_ensure_schema();
}

void
gatekeeper_sql_close(void)
{
	if (!authum_null_eq(g_db)) {
		sqlite3_close(g_db);
		g_db = authum_null;
	}
}

authum_bool_t
gatekeeper_sql_get_by_ip(const authum_char_t *ip, gatekeeper_iphub_data_t *out)
{
	authum_char_t sql[256];
	sqlite3_stmt *stmt = authum_null;
	int rc;

	if (authum_null_eq(g_db) || authum_null_eq(ip) || authum_null_eq(out))
		return authum_bool_false;

	gatekeeper_iphub_data_clear(out);
	snprintf(sql, sizeof sql, "SELECT id,asn,ip,code,name,isp,block FROM `%s` WHERE ip=? LIMIT 1",
		 g_gatekeeper_config.sql_table_ip);
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, authum_null) != SQLITE_OK)
		return authum_bool_false;

	sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		out->id = sqlite3_column_int(stmt, 0);
		out->asn = sqlite3_column_int(stmt, 1);
		authum_cstr_copy(out->ip, sizeof out->ip, (const authum_char_t *)sqlite3_column_text(stmt, 2));
		authum_cstr_copy(out->code, sizeof out->code,
				 (const authum_char_t *)sqlite3_column_text(stmt, 3));
		authum_cstr_copy(out->name, sizeof out->name,
				 (const authum_char_t *)sqlite3_column_text(stmt, 4));
		authum_cstr_copy(out->isp, sizeof out->isp,
				 (const authum_char_t *)sqlite3_column_text(stmt, 5));
		out->block = sqlite3_column_int(stmt, 6);
		sqlite3_finalize(stmt);
		return authum_bool_true;
	}
	sqlite3_finalize(stmt);
	return authum_bool_false;
}

authum_bool_t
gatekeeper_sql_insert_ip(gatekeeper_iphub_data_t *row)
{
	authum_char_t sql[256];
	sqlite3_stmt *stmt = authum_null;

	if (authum_null_eq(g_db) || authum_null_eq(row))
		return authum_bool_false;

	snprintf(sql, sizeof sql,
		 "INSERT INTO `%s` (asn,ip,code,name,isp,block) VALUES (?,?,?,?,?,?)",
		 g_gatekeeper_config.sql_table_ip);
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, authum_null) != SQLITE_OK)
		return authum_bool_false;

	sqlite3_bind_int(stmt, 1, row->asn);
	sqlite3_bind_text(stmt, 2, row->ip, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 3, row->code, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 4, row->name, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 5, row->isp, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int(stmt, 6, row->block);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		authum_logger_error(&g_gatekeeper_logger, "sql insert ip: %s", sqlite3_errmsg(g_db));
		sqlite3_finalize(stmt);
		return authum_bool_false;
	}
	row->id = (authum_i32_t)sqlite3_last_insert_rowid(g_db);
	sqlite3_finalize(stmt);
	return authum_bool_true;
}

authum_i32_t
gatekeeper_sql_ensure_client(authum_i32_t log_id, const authum_char_t *steamid)
{
	authum_char_t sql[256];
	sqlite3_stmt *stmt = authum_null;
	authum_i32_t id = -1;

	if (authum_null_eq(g_db) || authum_null_eq(steamid) || steamid[0] == '\0' || log_id < 0)
		return -1;

	snprintf(sql, sizeof sql, "SELECT id FROM `%s` WHERE steamid=? LIMIT 1",
		 g_gatekeeper_config.sql_table_client);
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, authum_null) != SQLITE_OK)
		return -1;
	sqlite3_bind_text(stmt, 1, steamid, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(stmt) == SQLITE_ROW)
		id = sqlite3_column_int(stmt, 0);
	sqlite3_finalize(stmt);
	if (id >= 0)
		return id;

	snprintf(sql, sizeof sql, "INSERT INTO `%s` (logid,steamid) VALUES (?,?)",
		 g_gatekeeper_config.sql_table_client);
	if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, authum_null) != SQLITE_OK)
		return -1;
	sqlite3_bind_int(stmt, 1, log_id);
	sqlite3_bind_text(stmt, 2, steamid, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(stmt) != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return -1;
	}
	id = (authum_i32_t)sqlite3_last_insert_rowid(g_db);
	sqlite3_finalize(stmt);
	return id;
}
