#include <gatekeeper/config.h>
#include <gatekeeper/host.h>

#include <authum/cfg.h>
#include <authum/cstr.h>
#include <authum/host.h>
#include <authum/null.h>
#include <authum/path.h>

gatekeeper_config_t g_gatekeeper_config = {
    .sql_driver = gatekeeper_sql_driver_sqlite,
    .sql_path = "gatekeeper.sqlite",
    .sql_host = "127.0.0.1",
    .sql_user = "root",
    .sql_pass = "",
    .sql_db = "gatekeeper",
    .sql_port = 3306,
    .sql_table_ip = "user",
    .sql_table_client = "client",
    .sql_table_session = "session",

    .iphub_api_key = "",
    .iphub_timeout_ms = 3000,
    .iphub_enabled = authum_bool_true,

    .filter_enabled = authum_bool_true,
    .filter_debug = authum_bool_false,
    .filter_block_max = 0,
    .filter_allow_countries = authum_bool_true,
    .filter_countries = "RU BY UA KZ KG MD UZ LV LT EE GE RO AM BG AZ TM TJ",
    .filter_kick_reason = "Access denied",
    .filter_whitelist = "whitelist.ini",

    .steam_guard_enabled = authum_bool_true,
    .steam_guard_enforce = authum_bool_false,
    .steam_guard_strict_country = authum_bool_false,
    .steam_guard_max_asn = 3,
    .steam_guard_kick_reason = "Steam session mismatch",

    .logging_sinks = authum_logger_sink_host | authum_logger_sink_file,
    .logging_split = authum_logger_file_split_full,
};

static const authum_cfg_item_t g_gatekeeper_config_items[] = {
    {"sql_path", authum_cfg_kind_cstr, g_gatekeeper_config.sql_path,
     sizeof g_gatekeeper_config.sql_path},
    {"sql_host", authum_cfg_kind_cstr, g_gatekeeper_config.sql_host,
     sizeof g_gatekeeper_config.sql_host},
    {"sql_user", authum_cfg_kind_cstr, g_gatekeeper_config.sql_user,
     sizeof g_gatekeeper_config.sql_user},
    {"sql_pass", authum_cfg_kind_cstr, g_gatekeeper_config.sql_pass,
     sizeof g_gatekeeper_config.sql_pass},
    {"sql_db", authum_cfg_kind_cstr, g_gatekeeper_config.sql_db, sizeof g_gatekeeper_config.sql_db},
    {"sql_port", authum_cfg_kind_i32, &g_gatekeeper_config.sql_port, 0},
    {"sql_table_ip", authum_cfg_kind_cstr, g_gatekeeper_config.sql_table_ip,
     sizeof g_gatekeeper_config.sql_table_ip},
    {"sql_table_client", authum_cfg_kind_cstr, g_gatekeeper_config.sql_table_client,
     sizeof g_gatekeeper_config.sql_table_client},
    {"sql_table_session", authum_cfg_kind_cstr, g_gatekeeper_config.sql_table_session,
     sizeof g_gatekeeper_config.sql_table_session},
    {"iphub_api_key", authum_cfg_kind_cstr, g_gatekeeper_config.iphub_api_key,
     sizeof g_gatekeeper_config.iphub_api_key},
    {"iphub_timeout_ms", authum_cfg_kind_i32, &g_gatekeeper_config.iphub_timeout_ms, 0},
    {"iphub_enabled", authum_cfg_kind_bool, &g_gatekeeper_config.iphub_enabled, 0},
    {"filter_enabled", authum_cfg_kind_bool, &g_gatekeeper_config.filter_enabled, 0},
    {"filter_debug", authum_cfg_kind_bool, &g_gatekeeper_config.filter_debug, 0},
    {"filter_block_max", authum_cfg_kind_i32, &g_gatekeeper_config.filter_block_max, 0},
    {"filter_allow_countries", authum_cfg_kind_bool, &g_gatekeeper_config.filter_allow_countries, 0},
    {"filter_countries", authum_cfg_kind_cstr, g_gatekeeper_config.filter_countries,
     sizeof g_gatekeeper_config.filter_countries},
    {"filter_kick_reason", authum_cfg_kind_cstr, g_gatekeeper_config.filter_kick_reason,
     sizeof g_gatekeeper_config.filter_kick_reason},
    {"filter_whitelist", authum_cfg_kind_cstr, g_gatekeeper_config.filter_whitelist,
     sizeof g_gatekeeper_config.filter_whitelist},
    {"steam_guard_enabled", authum_cfg_kind_bool, &g_gatekeeper_config.steam_guard_enabled, 0},
    {"steam_guard_enforce", authum_cfg_kind_bool, &g_gatekeeper_config.steam_guard_enforce, 0},
    {"steam_guard_strict_country", authum_cfg_kind_bool,
     &g_gatekeeper_config.steam_guard_strict_country, 0},
    {"steam_guard_max_asn", authum_cfg_kind_i32, &g_gatekeeper_config.steam_guard_max_asn, 0},
    {"steam_guard_kick_reason", authum_cfg_kind_cstr, g_gatekeeper_config.steam_guard_kick_reason,
     sizeof g_gatekeeper_config.steam_guard_kick_reason},
    {"logging_mode", authum_cfg_kind_u32, &g_gatekeeper_config.logging_sinks, 0},
};

static void
gatekeeper_config_apply_file(const authum_char_t *leaf)
{
    authum_path_t path;
    authum_cfg_t cfg;
    authum_char_t driver[32];
    authum_char_t split[32];

    if (!authum_path_join(&path, authum_host_env_module(&g_gatekeeper_host), leaf) ||
        !authum_cfg_open(&cfg, &path))
    {
        return;
    }

    authum_cfg_apply_items(
        &cfg, g_gatekeeper_config_items,
        (authum_usize_t)(sizeof g_gatekeeper_config_items / sizeof g_gatekeeper_config_items[0]));

    if (authum_cfg_apply_cstr(&cfg, "sql_driver", driver, sizeof driver))
    {
        if (authum_cstr_eq(driver, "mysql", authum_bool_true))
        {
            g_gatekeeper_config.sql_driver = gatekeeper_sql_driver_mysql;
        }
        else
        {
            g_gatekeeper_config.sql_driver = gatekeeper_sql_driver_sqlite;
        }
    }

    if (authum_cfg_apply_cstr(&cfg, "logging_split", split, sizeof split))
    {
        g_gatekeeper_config.logging_split = authum_logger_file_split_parse(split);
    }

    authum_cfg_close(&cfg);
    authum_logger_info(&g_gatekeeper_logger, "applied %s", leaf);
}

void
gatekeeper_config_load(void)
{
    gatekeeper_config_apply_file("gatekeeper.cfg");
    /* Secrets / overrides — gitignored locally, optional on the server. */
    gatekeeper_config_apply_file("gatekeeper.local.cfg");
    authum_logger_info(&g_gatekeeper_logger,
                       "cfg sql_driver=%s filter=%d steam_guard=%d enforce=%d max_asn=%d "
                       "iphub_api_key=%s",
                       g_gatekeeper_config.sql_driver == gatekeeper_sql_driver_mysql ? "mysql"
                                                                                    : "sqlite",
                       (int)g_gatekeeper_config.filter_enabled,
                       (int)g_gatekeeper_config.steam_guard_enabled,
                       (int)g_gatekeeper_config.steam_guard_enforce,
                       (int)g_gatekeeper_config.steam_guard_max_asn,
                       g_gatekeeper_config.iphub_api_key[0] ? "set" : "empty");
}
