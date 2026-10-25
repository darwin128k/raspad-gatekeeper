#include <gatekeeper/resolve.h>
#include <gatekeeper/client/state.h>
#include <gatekeeper/config.h>
#include <gatekeeper/event.h>
#include <gatekeeper/filter.h>
#include <gatekeeper/host.h>
#include <gatekeeper/iphub.h>
#include <gatekeeper/sql.h>
#include <gatekeeper/steam/guard.h>
#include <authum/cstr.h>
#include <authum/event/server.h>
#include <authum/sql/thread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum
{
    gatekeeper_job_log_max = 24
};
typedef struct gatekeeper_check_job
{
    authum_i32_t index, userid, client_row_id;
    authum_u32_t generation;
    authum_char_t ip[gatekeeper_ip_size], auth_id[64], reason[128];
    gatekeeper_iphub_data_t data;
    authum_bool_t resolved, deny;
    unsigned log_count, log_dropped;
    struct
    {
        authum_logger_level_t level;
        authum_char_t text[authum_logger_line_max];
    } logs[gatekeeper_job_log_max];
} gatekeeper_check_job_t;
static _Thread_local gatekeeper_check_job_t *g_worker_job;
static _Thread_local authum_logger_channel_t g_worker_channel;
static _Thread_local authum_logger_t g_worker_logger;
static authum_sql_connection_t g_connection;
static authum_path_t g_sql_path;

void
gatekeeper_worker_log_write(authum_ptr owner, authum_logger_level_t level,
                            const authum_char_t *text)
{
    gatekeeper_check_job_t *job = owner;
    if (job->log_count < gatekeeper_job_log_max)
    {
        unsigned i = job->log_count++;
        job->logs[i].level = level;
        authum_cstr_copy(job->logs[i].text, sizeof job->logs[i].text, text);
    }
    else
    {
        ++job->log_dropped;
    }
}
authum_bool_t
gatekeeper_worker_log_enabled(authum_ptr owner, authum_logger_level_t level)
{
    (void)owner;
    (void)level;
    return authum_bool_true;
}
authum_logger_t *
gatekeeper_log(void)
{
    return g_worker_job ? &g_worker_logger : &g_gatekeeper_logger;
}
void
gatekeeper_worker_logs_begin(gatekeeper_check_job_t *job)
{
    static const authum_logger_ops_t ops = {sizeof ops, gatekeeper_worker_log_write,
                                            gatekeeper_worker_log_enabled, 0, 0};
    g_worker_job = job;
    g_worker_channel.ops = &ops;
    g_worker_channel.owner = job;
    memset(&g_worker_logger, 0, sizeof g_worker_logger);
    g_worker_logger.channel = &g_worker_channel;
}

/** All database, whitelist-file and HTTP I/O happens in this worker. */
authum_bool_t
gatekeeper_check_work(authum_sql_t *db, authum_ptr user)
{
    gatekeeper_check_job_t *job = user;
    gatekeeper_filter_result_t filter;
    authum_bool_t ok = authum_bool_true;
    gatekeeper_worker_logs_begin(job);
    gatekeeper_sql_bind(db);
    if (!gatekeeper_sql_ensure_schema())
    {
        ok = authum_bool_false;
        goto done;
    }
    if (job->index == 0)
    {
        goto done; /* asynchronous startup/schema check */
    }
    job->resolved = gatekeeper_sql_get_by_ip(job->ip, &job->data);
    if (gatekeeper_sql_error()[0])
    {
        ok = authum_bool_false;
        goto done;
    }
    if (!job->resolved && g_gatekeeper_config.iphub_enabled)
    {
        job->resolved = gatekeeper_iphub_lookup(job->ip, &job->data);
        if (job->resolved && !gatekeeper_sql_insert_ip(&job->data))
        {
            authum_logger_error(gatekeeper_log(), "sql insert after iphub failed ip=%s", job->ip);
        }
    }
    if (!job->resolved)
    {
        goto done;
    }
    if (job->auth_id[0] && strcmp(job->auth_id, "BOT") && strcmp(job->auth_id, "HLTV") &&
        job->data.id >= 0)
    {
        job->client_row_id = gatekeeper_sql_ensure_client(job->data.id, job->auth_id);
    }
    filter = gatekeeper_filter_check(&job->data, job->auth_id);
    if (filter != gatekeeper_filter_result_allow)
    {
        job->deny = authum_bool_true;
        gatekeeper_filter_format_reject(filter, &job->data, job->reason, sizeof job->reason);
    }
    else if (!gatekeeper_steam_guard_allow(job->auth_id, &job->data))
    {
        job->deny = authum_bool_true;
        authum_cstr_copy(job->reason, sizeof job->reason,
                         g_gatekeeper_config.steam_guard_kick_reason);
    }
    if (gatekeeper_sql_error()[0])
    {
        authum_logger_error(gatekeeper_log(), "SQL check failed: %s", gatekeeper_sql_error());
        ok = authum_bool_false;
    }
done:
    gatekeeper_sql_bind(NULL);
    g_worker_job = NULL;
    return ok;
}

authum_bool_t
gatekeeper_check_is_current(const gatekeeper_check_job_t *job)
{
    gatekeeper_client_slot_t *slot = gatekeeper_client_slot(job->index);
    return job->userid > 0 && slot && slot->used && slot->generation == job->generation &&
           slot->userid == job->userid &&
           authum_host_client_userid(&g_gatekeeper_host, job->index) == job->userid;
}
void
gatekeeper_check_complete(const authum_sql_thread_result_t *result, authum_ptr user)
{
    gatekeeper_check_job_t *job = user;
    gatekeeper_client_slot_t *slot;
    unsigned i;
    for (i = 0; i < job->log_count; ++i)
    {
        authum_logger_log(gatekeeper_log(), job->logs[i].level, "%s", job->logs[i].text);
    }
    if (job->log_dropped)
    {
        authum_logger_warning(gatekeeper_log(), "SQL check log truncated (%u lines)",
                              job->log_dropped);
    }
    if (job->index == 0)
    {
        if (result->success)
        {
            authum_logger_info(gatekeeper_log(), "async SQL ready");
        }
        else
        {
            authum_logger_error(gatekeeper_log(),
                                "async SQL startup failed: %s; next player check will reconnect",
                                result->error);
        }
        return;
    }
    if (!gatekeeper_check_is_current(job))
    {
        return;
    }
    slot = gatekeeper_client_slot(job->index);
    slot->pending = authum_bool_false;
    if (!result->success)
    {
        authum_logger_error(gatekeeper_log(), "async SQL failed userid=%d ip=%s: %s; allow",
                            job->userid, job->ip, result->error);
        return;
    }
    if (!job->resolved)
    {
        authum_logger_warning(gatekeeper_log(), "resolve miss ip=%s - allow (no data)", job->ip);
        return;
    }
    slot->iphub = job->data;
    slot->client_row_id = job->client_row_id;
    {
        gatekeeper_event_resolved_t ev;
        memset(&ev, 0, sizeof ev);
        ev.size = sizeof ev;
        ev.index = job->index;
        ev.userid = job->userid;
        authum_cstr_copy(ev.auth_id, sizeof ev.auth_id, job->auth_id);
        ev.iphub = job->data;
        authum_host_publish(&g_gatekeeper_host, GATEKEEPER_EVENT_CLIENT_RESOLVED, &ev);
    }
    if (job->deny && gatekeeper_check_is_current(job))
    {
        authum_logger_info(gatekeeper_log(), "async kick userid=%d auth=%s ip=%s reason=%s",
                           job->userid, job->auth_id, job->ip, job->reason);
        authum_host_kick(&g_gatekeeper_host, job->userid, job->reason);
    }
}
void
gatekeeper_check_destroy(authum_ptr user)
{
    free(user);
}

authum_event_result_t
gatekeeper_on_map_end(const authum_char_t *name, authum_ptr payload, authum_ptr user)
{
    (void)name;
    (void)payload;
    (void)user;
    gatekeeper_client_state_start();
    return authum_event_result_continue;
}
authum_bool_t
gatekeeper_resolve_start(void)
{
    const authum_char_t *path = g_gatekeeper_config.sql_path;
    memset(&g_connection, 0, sizeof g_connection);
    g_connection.driver = g_gatekeeper_config.sql_driver == gatekeeper_sql_driver_mysql
                              ? authum_sql_driver_mysql
                              : authum_sql_driver_sqlite;
    g_connection.host = g_gatekeeper_config.sql_host;
    g_connection.user = g_gatekeeper_config.sql_user;
    g_connection.password = g_gatekeeper_config.sql_pass;
    g_connection.database = g_gatekeeper_config.sql_db;
    g_connection.port = (authum_u32_t)g_gatekeeper_config.sql_port;
    if (g_connection.driver == authum_sql_driver_sqlite)
    {
        authum_bool_t absolute = path[0] == '/' || path[0] == '\\' || (path[0] && path[1] == ':');
        if (!(absolute ? authum_path_set_cstr(&g_sql_path, path)
                       : authum_host_data_path(&g_gatekeeper_host, path, &g_sql_path)))
        {
            return authum_bool_false;
        }
        g_connection.path = authum_path_as_cstr(&g_sql_path);
    }
    if (!(authum_host_subscribe(&g_gatekeeper_host, AUTHUM_EVENT_CLIENT_CONNECT,
                                gatekeeper_on_client_connect, NULL) &&
          authum_host_subscribe(&g_gatekeeper_host, AUTHUM_EVENT_CLIENT_PUT_IN_SERVER,
                                gatekeeper_on_client_put_in_server, NULL) &&
          authum_host_subscribe(&g_gatekeeper_host, AUTHUM_EVENT_CLIENT_DISCONNECT,
                                gatekeeper_on_client_disconnect, NULL) &&
          authum_host_subscribe(&g_gatekeeper_host, AUTHUM_EVENT_SERVER_DEACTIVATE,
                                gatekeeper_on_map_end, NULL)))
    {
        return authum_bool_false;
    }
    {
        gatekeeper_check_job_t *job = calloc(1, sizeof *job);
        if (!job)
        {
            return authum_bool_false;
        }
        if (!authum_sql_thread_query(&g_gatekeeper_host, &g_connection, gatekeeper_check_work,
                                     gatekeeper_check_complete, gatekeeper_check_destroy, job))
        {
            free(job);
            return authum_bool_false;
        }
    }
    return authum_bool_true;
}
void
gatekeeper_resolve_stop(void)
{
}

authum_event_result_t
gatekeeper_on_client_connect(const authum_char_t *name, authum_ptr payload, authum_ptr user)
{
    const authum_event_client_t *ev = payload;
    gatekeeper_client_slot_t *slot;
    authum_usize_t i;
    (void)name;
    (void)user;
    if (!ev || ev->size < sizeof *ev || !(slot = gatekeeper_client_slot(ev->index)))
    {
        return authum_event_result_continue;
    }
    gatekeeper_client_slot_clear(ev->index);
    slot->used = authum_bool_true;
    slot->userid = ev->userid;
    for (i = 0; i + 1 < sizeof slot->ip && ev->address[i] && ev->address[i] != ':'; ++i)
    {
        slot->ip[i] = ev->address[i];
    }
    slot->ip[i] = '\0';
    return authum_event_result_continue;
}
authum_event_result_t
gatekeeper_on_client_put_in_server(const authum_char_t *name, authum_ptr payload, authum_ptr user)
{
    const authum_event_client_t *ev = payload;
    gatekeeper_client_slot_t *slot;
    gatekeeper_check_job_t *job;
    (void)name;
    (void)user;
    if (!ev || ev->size < sizeof *ev || !(slot = gatekeeper_client_slot(ev->index)) ||
        !slot->used || slot->pending || !slot->ip[0])
    {
        return authum_event_result_continue;
    }
    slot->userid = ev->userid;
    authum_cstr_copy(slot->auth_id, sizeof slot->auth_id, ev->auth_id);
    job = calloc(1, sizeof *job);
    if (!job)
    {
        authum_logger_error(gatekeeper_log(), "async check allocation failed; allow userid=%d",
                            ev->userid);
        return authum_event_result_continue;
    }
    job->index = ev->index;
    job->userid = ev->userid;
    job->generation = slot->generation;
    job->client_row_id = -1;
    authum_cstr_copy(job->ip, sizeof job->ip, slot->ip);
    authum_cstr_copy(job->auth_id, sizeof job->auth_id, slot->auth_id);
    slot->pending = authum_bool_true;
    if (!authum_sql_thread_query(&g_gatekeeper_host, &g_connection, gatekeeper_check_work,
                                 gatekeeper_check_complete, gatekeeper_check_destroy, job))
    {
        slot->pending = authum_bool_false;
        free(job);
        authum_logger_error(
            gatekeeper_log(),
            "async check queue unavailable/full (or MySQL client missing); allow userid=%d",
            ev->userid);
    }
    return authum_event_result_continue;
}
authum_event_result_t
gatekeeper_on_client_disconnect(const authum_char_t *name, authum_ptr payload, authum_ptr user)
{
    const authum_event_client_t *ev = payload;
    (void)name;
    (void)user;
    if (ev && ev->size >= sizeof *ev)
    {
        gatekeeper_client_slot_clear(ev->index);
    }
    return authum_event_result_continue;
}
