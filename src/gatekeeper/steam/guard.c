#include <gatekeeper/steam/guard.h>

#include <gatekeeper/config.h>
#include <gatekeeper/filter.h>
#include <gatekeeper/host.h>
#include <gatekeeper/sql.h>

#include <authum/cstr.h>
#include <authum/null.h>

static authum_bool_t
gatekeeper_steam_guard_prefix(const authum_char_t *auth_id, const authum_char_t *prefix)
{
    for (authum_usize_t i = 0u; prefix[i] != '\0'; ++i)
    {
        authum_char_t a = auth_id[i];
        authum_char_t b = prefix[i];
        if (a == '\0')
        {
            return authum_bool_false;
        }
        if (authum_char_to_lower(a) != authum_char_to_lower(b))
        {
            return authum_bool_false;
        }
    }
    return authum_bool_true;
}

authum_bool_t
gatekeeper_steam_guard_applicable(const authum_char_t *auth_id)
{
    if (authum_null_eq(auth_id) || auth_id[0] == '\0')
    {
        return authum_bool_false;
    }
    if (authum_cstr_is_equal(auth_id, "BOT", authum_bool_true) ||
        authum_cstr_is_equal(auth_id, "HLTV", authum_bool_true))
    {
        return authum_bool_false;
    }
    if (authum_cstr_contains(auth_id, "PENDING") || authum_cstr_contains(auth_id, "LAN"))
    {
        return authum_bool_false;
    }
    if (gatekeeper_steam_guard_prefix(auth_id, "STEAM_") ||
        gatekeeper_steam_guard_prefix(auth_id, "VALVE_"))
    {
        return authum_bool_true;
    }
    return authum_bool_false;
}

authum_bool_t
gatekeeper_steam_guard_allow(const authum_char_t *auth_id, const gatekeeper_iphub_data_t *data)
{
    if (!g_gatekeeper_config.steam_guard_enabled)
    {
        return authum_bool_true;
    }
    if (!gatekeeper_steam_guard_applicable(auth_id))
    {
        return authum_bool_true;
    }
    if (authum_null_eq(data) || data->id < 0)
    {
        /* No geo row — cannot judge; do not block. */
        return authum_bool_true;
    }

    if (gatekeeper_filter_whitelisted(data, auth_id))
    {
        gatekeeper_sql_session_touch(auth_id, data);
        return authum_bool_true;
    }

    if (gatekeeper_sql_session_has_asn(auth_id, data->asn))
    {
        gatekeeper_sql_session_touch(auth_id, data);
        return authum_bool_true;
    }

    {
        authum_i32_t asn_count = gatekeeper_sql_session_asn_count(auth_id);
        authum_bool_t known_code = gatekeeper_sql_session_has_code(auth_id, data->code);

        if (g_gatekeeper_config.steam_guard_strict_country && asn_count > 0 && !known_code)
        {
            authum_logger_warning(gatekeeper_log(),
                                  "steam_guard deny steamid=%s ip=%s asn=%d code=%s (new country)",
                                  auth_id, data->ip, (int)data->asn, data->code);
            if (!g_gatekeeper_config.steam_guard_enforce)
            {
                return authum_bool_true;
            }
            return authum_bool_false;
        }

        if (asn_count < g_gatekeeper_config.steam_guard_max_asn)
        {
            gatekeeper_sql_session_touch(auth_id, data);
            if (g_gatekeeper_config.filter_debug || asn_count > 0)
            {
                authum_logger_info(gatekeeper_log(),
                                   "steam_guard learn steamid=%s asn=%d code=%s (%d/%d)", auth_id,
                                   (int)data->asn, data->code, (int)asn_count + 1,
                                   (int)g_gatekeeper_config.steam_guard_max_asn);
            }
            return authum_bool_true;
        }
    }

    authum_logger_warning(gatekeeper_log(),
                          "steam_guard deny steamid=%s ip=%s asn=%d code=%s (asn budget %d)",
                          auth_id, data->ip, (int)data->asn, data->code,
                          (int)g_gatekeeper_config.steam_guard_max_asn);
    if (!g_gatekeeper_config.steam_guard_enforce)
    {
        return authum_bool_true;
    }
    return authum_bool_false;
}
