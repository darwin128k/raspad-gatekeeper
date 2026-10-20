#include <gatekeeper/sql.h>

#include <gatekeeper/config.h>
#include <gatekeeper/host.h>

#include <authum/cstr.h>
#include <authum/host.h>
#include <authum/null.h>
#include <authum/path.h>
#include <authum/sql.h>

#include <stdio.h>

static authum_sql_t g_db;

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
	if (!authum_sql_exec(&g_db, sql)) {
		authum_logger_error(&g_gatekeeper_logger, "sql schema ip: %s", authum_sql_errmsg(&g_db));
		return authum_bool_false;
	}

	snprintf(sql, sizeof sql,
		 "CREATE TABLE IF NOT EXISTS `%s` ("
		 "`id` INTEGER PRIMARY KEY AUTOINCREMENT,"
		 "`logid` INTEGER NOT NULL,"
		 "`steamid` TEXT NOT NULL UNIQUE"
		 ");",
		 g_gatekeeper_config.sql_table_client);
	if (!authum_sql_exec(&g_db, sql)) {
		authum_logger_error(&g_gatekeeper_logger, "sql schema client: %s",
				    authum_sql_errmsg(&g_db));
		return authum_bool_false;
	}
	return authum_bool_true;
}

authum_bool_t
gatekeeper_sql_open(void)
{
	authum_path_t path;

	if (g_gatekeeper_config.sql_driver == gatekeeper_sql_driver_mysql) {
		authum_logger_error(&g_gatekeeper_logger,
				    "SqlDriver=mysql not in Authum yet — use sqlite (SqlPath)");
		return authum_bool_false;
	}

	if (!authum_path_join(&path, authum_host_env_module(&g_gatekeeper_host),
			      g_gatekeeper_config.sql_path)) {
		authum_logger_error(&g_gatekeeper_logger, "sql: bad path");
		return authum_bool_false;
	}

	authum_sql_init(&g_db);
	if (!authum_sql_open_sqlite(&g_db, authum_path_as_cstr(&path))) {
		authum_logger_error(&g_gatekeeper_logger, "sql open FAILED: %s (%s)",
				    authum_sql_errmsg(&g_db), authum_path_as_cstr(&path));
		return authum_bool_false;
	}

	authum_logger_info(&g_gatekeeper_logger, "sql open (authum sqlite): %s",
			   authum_path_as_cstr(&path));
	return gatekeeper_sql_ensure_schema();
}

void
gatekeeper_sql_close(void)
{
	authum_sql_close(&g_db);
}

authum_bool_t
gatekeeper_sql_get_by_ip(const authum_char_t *ip, gatekeeper_iphub_data_t *out)
{
	authum_char_t sql[256];
	authum_sql_stmt_t stmt;

	if (!authum_sql_is_open(&g_db) || authum_null_eq(ip) || authum_null_eq(out))
		return authum_bool_false;

	gatekeeper_iphub_data_clear(out);
	snprintf(sql, sizeof sql, "SELECT id,asn,ip,code,name,isp,block FROM `%s` WHERE ip=? LIMIT 1",
		 g_gatekeeper_config.sql_table_ip);
	if (!authum_sql_prepare(&g_db, &stmt, sql))
		return authum_bool_false;

	authum_sql_stmt_bind_cstr(&stmt, 1, ip);
	if (authum_sql_stmt_step_row(&stmt)) {
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

	if (!authum_sql_is_open(&g_db) || authum_null_eq(row))
		return authum_bool_false;

	snprintf(sql, sizeof sql,
		 "INSERT INTO `%s` (asn,ip,code,name,isp,block) VALUES (?,?,?,?,?,?)",
		 g_gatekeeper_config.sql_table_ip);
	if (!authum_sql_prepare(&g_db, &stmt, sql))
		return authum_bool_false;

	authum_sql_stmt_bind_i32(&stmt, 1, row->asn);
	authum_sql_stmt_bind_cstr(&stmt, 2, row->ip);
	authum_sql_stmt_bind_cstr(&stmt, 3, row->code);
	authum_sql_stmt_bind_cstr(&stmt, 4, row->name);
	authum_sql_stmt_bind_cstr(&stmt, 5, row->isp);
	authum_sql_stmt_bind_i32(&stmt, 6, row->block);

	if (!authum_sql_stmt_step_done(&stmt)) {
		authum_logger_error(&g_gatekeeper_logger, "sql insert ip: %s", authum_sql_errmsg(&g_db));
		authum_sql_stmt_finalize(&stmt);
		return authum_bool_false;
	}
	row->id = (authum_i32_t)authum_sql_last_insert_id(&g_db);
	authum_sql_stmt_finalize(&stmt);
	return authum_bool_true;
}

authum_i32_t
gatekeeper_sql_ensure_client(authum_i32_t log_id, const authum_char_t *steamid)
{
	authum_char_t sql[256];
	authum_sql_stmt_t stmt;
	authum_i32_t id = -1;

	if (!authum_sql_is_open(&g_db) || authum_null_eq(steamid) || steamid[0] == '\0' || log_id < 0)
		return -1;

	snprintf(sql, sizeof sql, "SELECT id FROM `%s` WHERE steamid=? LIMIT 1",
		 g_gatekeeper_config.sql_table_client);
	if (!authum_sql_prepare(&g_db, &stmt, sql))
		return -1;
	authum_sql_stmt_bind_cstr(&stmt, 1, steamid);
	if (authum_sql_stmt_step_row(&stmt))
		id = authum_sql_stmt_column_i32(&stmt, 0);
	authum_sql_stmt_finalize(&stmt);
	if (id >= 0)
		return id;

	snprintf(sql, sizeof sql, "INSERT INTO `%s` (logid,steamid) VALUES (?,?)",
		 g_gatekeeper_config.sql_table_client);
	if (!authum_sql_prepare(&g_db, &stmt, sql))
		return -1;
	authum_sql_stmt_bind_i32(&stmt, 1, log_id);
	authum_sql_stmt_bind_cstr(&stmt, 2, steamid);
	if (!authum_sql_stmt_step_done(&stmt)) {
		authum_sql_stmt_finalize(&stmt);
		return -1;
	}
	id = (authum_i32_t)authum_sql_last_insert_id(&g_db);
	authum_sql_stmt_finalize(&stmt);
	return id;
}
