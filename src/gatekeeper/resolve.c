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
#include <authum/event/client.h>
#include <authum/host.h>
#include <authum/null.h>

#include <string.h>

static void
gatekeeper_strip_port(const authum_char_t *address, authum_char_t *ip, authum_usize_t ip_size)
{
    authum_usize_t i;

    if (authum_null_eq(address) || authum_null_eq(ip) || ip_size == 0u)
    {
        if (!authum_null_eq(ip) && ip_size > 0u)
        {
            ip[0] = '\0';
        }
        return;
    }
    /* skip [ipv6] for now; classic HLDS is ipv4 host:port */
    for (i = 0; i + 1u < ip_size && address[i] && address[i] != ':'; ++i)
    {
        ip[i] = address[i];
    }
    ip[i] = '\0';
}

static authum_bool_t
gatekeeper_resolve_ip(const authum_char_t *ip, gatekeeper_iphub_data_t *out)
{
    if (authum_null_eq(ip) || ip[0] == '\0')
    {
        return authum_bool_false;
    }

    if (gatekeeper_sql_get_by_ip(ip, out))
    {
        return authum_bool_true;
    }

    if (!g_gatekeeper_config.iphub_enabled)
    {
        return authum_bool_false;
    }

    if (!gatekeeper_iphub_lookup(ip, out))
    {
        return authum_bool_false;
    }

    if (!gatekeeper_sql_insert_ip(out))
    {
        authum_logger_error(&g_gatekeeper_logger, "sql insert after iphub failed ip=%s", ip);
    }
    return authum_bool_true;
}

static void
gatekeeper_publish_resolved(authum_i32_t index, authum_i32_t userid, const authum_char_t *auth_id,
                            const gatekeeper_iphub_data_t *iphub)
{
    gatekeeper_event_resolved_t ev;

    memset(&ev, 0, sizeof ev);
    ev.size = sizeof ev;
    ev.index = index;
    ev.userid = userid;
    if (!authum_null_eq(auth_id))
    {
        authum_cstr_copy(ev.auth_id, sizeof ev.auth_id, auth_id);
    }
    if (!authum_null_eq(iphub))
    {
        ev.iphub = *iphub;
    }
    authum_host_publish(&g_gatekeeper_host, GATEKEEPER_EVENT_CLIENT_RESOLVED, &ev);
}

static void
gatekeeper_bind_client_row(gatekeeper_client_slot_t *slot, const authum_char_t *auth_id)
{
    if (authum_null_eq(slot) || authum_null_eq(auth_id) || auth_id[0] == '\0')
    {
        return;
    }
    if (authum_cstr_eq(auth_id, "BOT", authum_bool_true) ||
        authum_cstr_eq(auth_id, "HLTV", authum_bool_true))
    {
        return;
    }
    if (slot->iphub.id < 0)
    {
        return;
    }
    authum_cstr_copy(slot->auth_id, sizeof slot->auth_id, auth_id);
    slot->client_row_id = gatekeeper_sql_ensure_client(slot->iphub.id, auth_id);
}

authum_bool_t
gatekeeper_resolve_start(void)
{
    return authum_host_subscribe(&g_gatekeeper_host, AUTHUM_EVENT_CLIENT_CONNECT,
                                 gatekeeper_on_client_connect, authum_null) &&
           authum_host_subscribe(&g_gatekeeper_host, AUTHUM_EVENT_CLIENT_PUT_IN_SERVER,
                                 gatekeeper_on_client_put_in_server, authum_null) &&
           authum_host_subscribe(&g_gatekeeper_host, AUTHUM_EVENT_CLIENT_DISCONNECT,
                                 gatekeeper_on_client_disconnect, authum_null);
}

void
gatekeeper_resolve_stop(void)
{
}

authum_event_result_t
gatekeeper_on_client_connect(const authum_char_t *name, authum_ptr payload, authum_ptr user)
{
    authum_event_client_t *ev = (authum_event_client_t *)payload;
    gatekeeper_client_slot_t *slot;
    authum_char_t ip[gatekeeper_ip_size];

    (void)name;
    (void)user;
    if (authum_null_eq(ev) || ev->size < sizeof *ev)
    {
        return authum_event_result_continue;
    }

    slot = gatekeeper_client_slot(ev->index);
    if (authum_null_eq(slot))
    {
        return authum_event_result_continue;
    }

    gatekeeper_client_slot_clear(ev->index);
    slot->used = authum_bool_true;
    slot->userid = ev->userid;
    gatekeeper_strip_port(ev->address, ip, sizeof ip);

    if (!gatekeeper_resolve_ip(ip, &slot->iphub))
    {
        authum_logger_warning(&g_gatekeeper_logger, "resolve miss ip=%s — allow (no data)", ip);
        return authum_event_result_continue;
    }

    gatekeeper_bind_client_row(slot, ev->auth_id);
    gatekeeper_publish_resolved(ev->index, ev->userid, ev->auth_id, &slot->iphub);

    {
        gatekeeper_filter_result_t fr = gatekeeper_filter_check(&slot->iphub, ev->auth_id);
        if (fr != gatekeeper_filter_result_allow)
        {
            gatekeeper_filter_format_reject(fr, &slot->iphub, ev->reject_reason,
                                            sizeof ev->reject_reason);
            authum_logger_info(&g_gatekeeper_logger,
                               "reject connect (filter) userid=%d auth=%s ip=%s reason=%s",
                               ev->userid, ev->auth_id[0] ? ev->auth_id : "?", slot->iphub.ip,
                               ev->reject_reason);
            ev->allow = authum_bool_false;
            return authum_event_result_handled;
        }
    }
    if (!gatekeeper_steam_guard_allow(ev->auth_id, &slot->iphub))
    {
        authum_logger_info(&g_gatekeeper_logger,
                           "reject connect (steam_guard) userid=%d auth=%s ip=%s reason=%s",
                           ev->userid, ev->auth_id[0] ? ev->auth_id : "?", slot->iphub.ip,
                           g_gatekeeper_config.steam_guard_kick_reason);
        ev->allow = authum_bool_false;
        authum_cstr_copy(ev->reject_reason, sizeof ev->reject_reason,
                         g_gatekeeper_config.steam_guard_kick_reason);
        return authum_event_result_handled;
    }
    return authum_event_result_continue;
}

authum_event_result_t
gatekeeper_on_client_put_in_server(const authum_char_t *name, authum_ptr payload, authum_ptr user)
{
    const authum_event_client_t *ev = (const authum_event_client_t *)payload;
    gatekeeper_client_slot_t *slot;

    (void)name;
    (void)user;
    if (authum_null_eq(ev) || ev->size < sizeof *ev)
    {
        return authum_event_result_continue;
    }

    slot = gatekeeper_client_slot(ev->index);
    if (authum_null_eq(slot) || !slot->used)
    {
        return authum_event_result_continue;
    }

    slot->userid = ev->userid;
    gatekeeper_bind_client_row(slot, ev->auth_id);

    if (slot->iphub.id >= 0)
    {
        gatekeeper_filter_result_t fr = gatekeeper_filter_check(&slot->iphub, ev->auth_id);
        if (fr != gatekeeper_filter_result_allow)
        {
            authum_char_t reason[128];
            gatekeeper_filter_format_reject(fr, &slot->iphub, reason, sizeof reason);
            authum_logger_info(&g_gatekeeper_logger,
                               "kick in-server (filter) userid=%d auth=%s ip=%s reason=%s",
                               ev->userid, ev->auth_id[0] ? ev->auth_id : "?", slot->iphub.ip,
                               reason);
            authum_host_kick(&g_gatekeeper_host, ev->userid, reason);
            return authum_event_result_handled;
        }
    }
    if (slot->iphub.id >= 0 && !gatekeeper_steam_guard_allow(ev->auth_id, &slot->iphub))
    {
        authum_logger_info(&g_gatekeeper_logger,
                           "kick in-server (steam_guard) userid=%d auth=%s ip=%s reason=%s",
                           ev->userid, ev->auth_id[0] ? ev->auth_id : "?", slot->iphub.ip,
                           g_gatekeeper_config.steam_guard_kick_reason);
        authum_host_kick(&g_gatekeeper_host, ev->userid,
                         g_gatekeeper_config.steam_guard_kick_reason);
        return authum_event_result_handled;
    }
    return authum_event_result_continue;
}

authum_event_result_t
gatekeeper_on_client_disconnect(const authum_char_t *name, authum_ptr payload, authum_ptr user)
{
    const authum_event_client_t *ev = (const authum_event_client_t *)payload;

    (void)name;
    (void)user;
    if (authum_null_eq(ev) || ev->size < sizeof *ev)
    {
        return authum_event_result_continue;
    }
    gatekeeper_client_slot_clear(ev->index);
    return authum_event_result_continue;
}
