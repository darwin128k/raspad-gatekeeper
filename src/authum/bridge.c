#include <gatekeeper/bridge.h>

#include <gatekeeper/client/state.h>
#include <gatekeeper/config.h>
#include <gatekeeper/host.h>
#include <gatekeeper/resolve.h>
#include <gatekeeper/sql.h>

#include <authum/host.h>
#include <authum/logger.h>
#include <authum/null.h>
#include <authum/path.h>

authum_host_t g_gatekeeper_host;
authum_logger_t g_gatekeeper_logger;

authum_bool_t
gatekeeper_authum_start(authum_host_t *host)
{
    if (authum_null_eq(host))
    {
        return authum_bool_false;
    }

    authum_host_copy(&g_gatekeeper_host, host);
    authum_logger_init(&g_gatekeeper_logger, &g_gatekeeper_host);

    if (authum_null_eq(authum_host_env(&g_gatekeeper_host)) ||
        authum_null_eq(authum_host_events(&g_gatekeeper_host)) ||
        authum_null_eq(authum_host_commands(&g_gatekeeper_host)) ||
        authum_null_eq(authum_host_sandbox(&g_gatekeeper_host)))
    {
        authum_logger_error(&g_gatekeeper_logger,
                            "host facade incomplete (needs env/events/commands/sandbox)");
        return authum_bool_false;
    }

    gatekeeper_config_load();

    authum_logger_info(&g_gatekeeper_logger, "start — module dir: %s",
                       authum_path_as_cstr(authum_host_env_module(&g_gatekeeper_host)));

    if (!gatekeeper_sql_open())
    {
        authum_logger_error(&g_gatekeeper_logger, "sql open FAILED");
        return authum_bool_false;
    }
    if (!gatekeeper_client_state_start() || !gatekeeper_resolve_start())
    {
        authum_logger_error(&g_gatekeeper_logger, "client state / subscriptions FAILED");
        gatekeeper_sql_close();
        return authum_bool_false;
    }

    authum_logger_info(&g_gatekeeper_logger, "ready (sql + iphub + filter + steam_guard)");
    return authum_bool_true;
}

void
gatekeeper_authum_stop(void)
{
    gatekeeper_resolve_stop();
    gatekeeper_client_state_stop();
    gatekeeper_sql_close();
    authum_logger_info(&g_gatekeeper_logger, "stop");
    authum_logger_close(&g_gatekeeper_logger);
    authum_host_clear(&g_gatekeeper_host);
}
