#ifndef GATEKEEPER_CONFIG_H
#define GATEKEEPER_CONFIG_H

#include <authum/bool.h>
#include <authum/byte.h>
#include <authum/char.h>

enum gatekeeper_sql_driver
{
    gatekeeper_sql_driver_sqlite = 0,
    gatekeeper_sql_driver_mysql = 1
};
typedef enum gatekeeper_sql_driver gatekeeper_sql_driver_t;

struct gatekeeper_config
{
    gatekeeper_sql_driver_t sql_driver;
    /* sqlite: path under module dir (default gatekeeper.sqlite) */
    authum_char_t sql_path[256];
    /* mysql (Authum dlopen of host libmariadb / libmysqlclient): */
    authum_char_t sql_host[128];
    authum_char_t sql_user[64];
    authum_char_t sql_pass[64];
    authum_char_t sql_db[64];
    authum_i32_t sql_port; /* 0 → 3306 */
    /* Wait for mysqld when HLDS and MariaDB start together: */
    authum_i32_t sql_connect_delay_ms; /* sleep before first open (0 = none) */
    authum_i32_t sql_connect_retries; /* total attempts (≥1); default 1 */
    authum_i32_t sql_connect_retry_ms; /* pause between failed attempts */
    authum_char_t sql_table_ip[32];
    authum_char_t sql_table_client[32];
    authum_char_t sql_table_session[32]; /* steamid↔ASN history */

    authum_char_t iphub_api_key[128];
    authum_i32_t iphub_timeout_ms;
    authum_bool_t iphub_enabled;

    authum_bool_t filter_enabled;
    authum_bool_t filter_debug;
    authum_i32_t filter_block_max; /* kick when iphub block > this */
    authum_bool_t filter_allow_countries; /* true = list is allow-list */
    authum_char_t filter_countries[512];
    authum_char_t filter_kick_reason[128];
    authum_char_t filter_whitelist[64]; /* leaf under module dir */

    /* Stolen / shared Steam ticket: learn ASN(+country) per steamid. */
    authum_bool_t steam_guard_enabled;
    authum_bool_t steam_guard_enforce; /* 0 = log only; 1 = reject */
    authum_bool_t steam_guard_strict_country; /* new country never seen → deny when enforce */
    authum_i32_t steam_guard_max_asn; /* distinct ASNs allowed before deny */
    authum_char_t steam_guard_kick_reason[128];

};
typedef struct gatekeeper_config gatekeeper_config_t;

extern gatekeeper_config_t g_gatekeeper_config;

void
gatekeeper_config_load(void);

#endif /* GATEKEEPER_CONFIG_H */
