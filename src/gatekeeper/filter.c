#include <gatekeeper/filter.h>

#include <gatekeeper/config.h>
#include <gatekeeper/host.h>

#include <authum/cstr.h>
#include <authum/file.h>
#include <authum/host.h>
#include <authum/null.h>
#include <authum/path.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static authum_bool_t
gatekeeper_filter_country_denied(const authum_char_t *code)
{
    authum_char_t upper[8];
    authum_usize_t i;

    if (authum_null_eq(code) || code[0] == '\0')
    {
        return authum_bool_false;
    }

    for (i = 0; i < sizeof upper - 1u && code[i]; ++i)
    {
        upper[i] = (authum_char_t)toupper((unsigned char)code[i]);
    }
    upper[i] = '\0';

    if (g_gatekeeper_config.filter_allow_countries)
    {
        return strstr(g_gatekeeper_config.filter_countries, upper) == authum_null
                   ? authum_bool_true
                   : authum_bool_false;
    }
    return strstr(g_gatekeeper_config.filter_countries, upper) != authum_null ? authum_bool_true
                                                                              : authum_bool_false;
}

static authum_i32_t
gatekeeper_filter_read_flags(const authum_char_t *s)
{
    authum_i32_t flags = 0;

    for (; s && *s; ++s)
    {
        authum_char_t c = (authum_char_t)tolower((unsigned char)*s);
        if (c == 'a')
        {
            flags |= 1 << 0;
        }
        else if (c == 'b')
        {
            flags |= 1 << 1;
        }
        else if (c == 'i')
        {
            flags |= 1 << 2;
        }
        else if (c == 's')
        {
            flags |= 1 << 3;
        }
    }
    return flags;
}

/** The whitelist file is read whole; a bigger one is refused. */
#define GATEKEEPER_FILTER_WHITELIST_MAX 65536u

/** One whitelist line: `flags asn ip auth_id block`; true when it matches. */
static authum_bool_t
gatekeeper_filter_whitelist_line(const authum_char_t *line, const gatekeeper_iphub_data_t *data,
                                 const authum_char_t *auth_id)
{
    authum_char_t flags_s[16], asn_s[16], ip_s[48], auth_s[64], block_s[8];
    authum_i32_t flags;
    int n;

    if (line[0] == ';' || line[0] == '#' || line[0] == '\n' || line[0] == '\r')
    {
        return authum_bool_false;
    }
    flags_s[0] = asn_s[0] = ip_s[0] = auth_s[0] = block_s[0] = '\0';
    n = sscanf(line, "%15s %15s %47s %63s %7s", flags_s, asn_s, ip_s, auth_s, block_s);
    if (n < 1 || flags_s[0] == '\0')
    {
        return authum_bool_false;
    }
    flags = gatekeeper_filter_read_flags(flags_s);
    if (flags == 0)
    {
        return authum_bool_false;
    }
    if ((flags & (1 << 0)) && atoi(asn_s) != data->asn)
    {
        return authum_bool_false;
    }
    if ((flags & (1 << 2)) && !authum_cstr_is_equal(ip_s, data->ip, authum_bool_false))
    {
        return authum_bool_false;
    }
    if ((flags & (1 << 3)) &&
        (authum_null_eq(auth_id) || !authum_cstr_is_equal(auth_s, auth_id, authum_bool_true)))
    {
        return authum_bool_false;
    }
    if ((flags & (1 << 1)) && atoi(block_s) != data->block)
    {
        return authum_bool_false;
    }
    return authum_bool_true;
}

authum_bool_t
gatekeeper_filter_whitelisted(const gatekeeper_iphub_data_t *data, const authum_char_t *auth_id)
{
    authum_path_t path;
    authum_file_t file;
    authum_char_t text[GATEKEEPER_FILTER_WHITELIST_MAX];
    authum_usize_t total = 0u;
    authum_char_t *line;

    /* modules/gatekeeper/configs/whitelist.ini */
    if (!authum_host_join_config_path(&g_gatekeeper_host, g_gatekeeper_config.filter_whitelist, &path))
    {
        return authum_bool_false;
    }

    authum_file_init(&file);
    if (!authum_file_open(&file, &path, authum_file_mode_read))
    {
        authum_file_close(&file);
        return authum_bool_false;
    }
    if (!authum_file_read_all(&file, text, sizeof text, &total) || total >= sizeof text)
    {
        authum_file_close(&file);
        authum_logger_error(gatekeeper_log(), "whitelist too large: %s",
                            g_gatekeeper_config.filter_whitelist);
        return authum_bool_false;
    }
    authum_file_close(&file);

    for (line = text; *line != '\0';)
    {
        authum_char_t *newline = strchr(line, '\n');

        if (newline != authum_null)
        {
            *newline = '\0';
        }
        if (gatekeeper_filter_whitelist_line(line, data, auth_id))
        {
            return authum_bool_true;
        }
        if (newline == authum_null)
        {
            break;
        }
        line = newline + 1;
    }
    return authum_bool_false;
}

gatekeeper_filter_result_t
gatekeeper_filter_check(const gatekeeper_iphub_data_t *data, const authum_char_t *auth_id)
{
    if (!g_gatekeeper_config.filter_enabled)
    {
        return gatekeeper_filter_result_allow;
    }
    if (authum_null_eq(data))
    {
        return gatekeeper_filter_result_allow;
    }

    if (gatekeeper_filter_whitelisted(data, auth_id))
    {
        if (g_gatekeeper_config.filter_debug)
        {
            authum_logger_info(gatekeeper_log(), "filter allow whitelist ip=%s asn=%d",
                               data->ip, (int)data->asn);
        }
        return gatekeeper_filter_result_allow;
    }

    if (gatekeeper_filter_country_denied(data->code))
    {
        authum_logger_info(gatekeeper_log(),
                           "filter DENY country ip=%s code=%s asn=%d block=%d isp=%s", data->ip,
                           data->code[0] ? data->code : "?", (int)data->asn, (int)data->block,
                           data->isp);
        return gatekeeper_filter_result_deny_country;
    }
    if (data->block > g_gatekeeper_config.filter_block_max)
    {
        authum_logger_info(gatekeeper_log(),
                           "filter DENY block ip=%s code=%s asn=%d block=%d (max=%d) isp=%s",
                           data->ip, data->code[0] ? data->code : "?", (int)data->asn,
                           (int)data->block, (int)g_gatekeeper_config.filter_block_max, data->isp);
        return gatekeeper_filter_result_deny_block;
    }
    return gatekeeper_filter_result_allow;
}

authum_bool_t
gatekeeper_filter_allow(const gatekeeper_iphub_data_t *data, const authum_char_t *auth_id)
{
    return gatekeeper_filter_check(data, auth_id) == gatekeeper_filter_result_allow
               ? authum_bool_true
               : authum_bool_false;
}

void
gatekeeper_filter_format_reject(gatekeeper_filter_result_t result,
                                const gatekeeper_iphub_data_t *data, authum_char_t *buf,
                                authum_usize_t buf_size)
{
    const authum_char_t *code;

    if (authum_null_eq(buf) || buf_size == 0u)
    {
        return;
    }

    /* Engine shows: "… because: <reject_reason>" — reason must stand alone. */
    code = (!authum_null_eq(data) && data->code[0]) ? data->code : "?";

    if (result == gatekeeper_filter_result_deny_country)
    {
        snprintf(buf, (size_t)buf_size, "country %s is not allowed", code);
        return;
    }
    if (result == gatekeeper_filter_result_deny_block && !authum_null_eq(data))
    {
        snprintf(buf, (size_t)buf_size, "proxy/VPN is not allowed (block %d)", (int)data->block);
        return;
    }
    if (g_gatekeeper_config.filter_kick_reason[0] != '\0')
    {
        authum_cstr_copy(buf, buf_size, g_gatekeeper_config.filter_kick_reason);
        return;
    }
    authum_cstr_copy(buf, buf_size, "access denied");
}
