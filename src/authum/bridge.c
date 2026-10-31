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
    authum_logger_init(gatekeeper_log(), &g_gatekeeper_host);

    if (authum_null_eq(authum_host_get_env(&g_gatekeeper_host)) ||
        authum_null_eq(authum_host_get_events(&g_gatekeeper_host)) ||
        authum_null_eq(authum_host_get_commands(&g_gatekeeper_host)) ||
        authum_null_eq(authum_host_get_sandbox(&g_gatekeeper_host)))
    {
        authum_logger_error(gatekeeper_log(),
                            "host facade incomplete (needs env/events/commands/sandbox)");
        return authum_bool_false;
    }

    gatekeeper_config_load();

    authum_logger_info(gatekeeper_log(), "start — data dir: %s",
                       authum_path_get_cstr(authum_host_get_module_data_path(&g_gatekeeper_host)));

    if (!authum_host_get_tasks(&g_gatekeeper_host))
    {
        authum_logger_error(gatekeeper_log(), "host has no background task API; update Authum");
        return authum_bool_false;
    }
    if (!gatekeeper_client_state_start() || !gatekeeper_resolve_start())
    {
        authum_logger_error(gatekeeper_log(), "client state / subscriptions FAILED");
        return authum_bool_false;
    }

    authum_logger_info(gatekeeper_log(), "ready (async sql + iphub; checks after put-in-server)");
    return authum_bool_true;
}

void
gatekeeper_authum_stop(void)
{
    gatekeeper_resolve_stop();
    gatekeeper_client_state_stop();
    authum_logger_info(gatekeeper_log(), "stop");
    authum_logger_close(gatekeeper_log());
    authum_host_clear(&g_gatekeeper_host);
}
