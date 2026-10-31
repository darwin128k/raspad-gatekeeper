#include <gatekeeper/iphub.h>

#include <gatekeeper/config.h>
#include <gatekeeper/host.h>

#include <authum/cstr.h>
#include <authum/json.h>
#include <authum/null.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#    include <winsock2.h>
#    include <ws2tcpip.h>
#else
#    include <arpa/inet.h>
#    include <netdb.h>
#    include <sys/socket.h>
#    include <sys/time.h>
#    include <unistd.h>
#endif

/** The socket handle of the platform; POSIX has no type of its own. */
#ifdef _WIN32
typedef SOCKET gatekeeper_socket_t;
#    define GATEKEEPER_SOCKET_INVALID INVALID_SOCKET
#    define GATEKEEPER_SOCKET_CLOSE(socket) closesocket(socket)
#else
typedef int gatekeeper_socket_t;
#    define GATEKEEPER_SOCKET_INVALID (-1)
#    define GATEKEEPER_SOCKET_CLOSE(socket) close(socket)
#endif

/** Winsock needs a start before the first socket and a stop after the last. */
static authum_bool_t
gatekeeper_iphub_net_start(void)
{
#ifdef _WIN32
    WSADATA data;

    return WSAStartup(MAKEWORD(2, 2), &data) == 0 ? authum_bool_true : authum_bool_false;
#else
    return authum_bool_true;
#endif
}

static void
gatekeeper_iphub_net_stop(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

/** Ask IPHub about @p ip; the whole answer lands in @p buf. */
static authum_bool_t
gatekeeper_iphub_fetch(const authum_char_t *ip, authum_char_t *buf, authum_usize_t buf_size)
{
    struct addrinfo hints, *addresses = authum_null;
    struct sockaddr_in addr;
    gatekeeper_socket_t fd = GATEKEEPER_SOCKET_INVALID;
    authum_char_t req[512];
    authum_usize_t total = 0u;
    int n;
    struct timeval tv;
    authum_bool_t ok = authum_bool_false;

    if (!gatekeeper_iphub_net_start())
    {
        authum_logger_error(gatekeeper_log(), "iphub: socket layer unavailable");
        return authum_bool_false;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("v2.api.iphub.info", "80", &hints, &addresses) != 0 || !addresses)
    {
        authum_logger_error(gatekeeper_log(), "iphub: DNS failed");
        goto done;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == GATEKEEPER_SOCKET_INVALID)
    {
        freeaddrinfo(addresses);
        goto done;
    }

    tv.tv_sec = (time_t)(g_gatekeeper_config.iphub_timeout_ms / 1000);
    tv.tv_usec = (long)(g_gatekeeper_config.iphub_timeout_ms % 1000) * 1000L;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, (int)sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, (int)sizeof tv);

    memcpy(&addr, addresses->ai_addr, sizeof addr);
    freeaddrinfo(addresses);

    if (connect(fd, (struct sockaddr *)&addr, (int)sizeof addr) != 0)
    {
        authum_logger_error(gatekeeper_log(), "iphub: connect failed");
        goto done;
    }

    snprintf(req, sizeof req,
             "GET /ip/%s HTTP/1.0\r\n"
             "Host: v2.api.iphub.info\r\n"
             "X-Key: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             ip, g_gatekeeper_config.iphub_api_key);

    if (send(fd, req, (int)strlen(req), 0) < 0)
    {
        goto done;
    }

    while (total + 1u < buf_size)
    {
        n = recv(fd, buf + total, (int)(buf_size - total - 1u), 0);
        if (n <= 0)
        {
            break;
        }
        total += (authum_usize_t)n;
    }
    buf[total] = '\0';

    if (strstr(buf, "HTTP/1.0 200") == authum_null && strstr(buf, "HTTP/1.1 200") == authum_null)
    {
        authum_logger_error(gatekeeper_log(), "iphub: bad HTTP status (ip=%s)", ip);
        goto done;
    }
    ok = authum_bool_true;

done:
    if (fd != GATEKEEPER_SOCKET_INVALID)
    {
        GATEKEEPER_SOCKET_CLOSE(fd);
    }
    gatekeeper_iphub_net_stop();
    return ok;
}

authum_bool_t
gatekeeper_iphub_lookup(const authum_char_t *ip, gatekeeper_iphub_data_t *out)
{
    authum_char_t buf[4096];
    const authum_char_t *body;

    if (authum_null_eq(ip) || authum_null_eq(out) || g_gatekeeper_config.iphub_api_key[0] == '\0')
    {
        return authum_bool_false;
    }

    gatekeeper_iphub_data_clear(out);
    authum_cstr_copy(out->ip, sizeof out->ip, ip);

    if (!gatekeeper_iphub_fetch(ip, buf, sizeof buf))
    {
        return authum_bool_false;
    }

    body = strstr(buf, "\r\n\r\n");
    if (authum_null_eq(body))
    {
        authum_logger_error(gatekeeper_log(), "iphub: no body");
        return authum_bool_false;
    }
    body += 4;

    authum_json_object_copy_cstr(body, "countryCode", out->code, sizeof out->code);
    authum_json_object_copy_cstr(body, "countryName", out->name, sizeof out->name);
    authum_json_object_copy_cstr(body, "isp", out->isp, sizeof out->isp);
    out->asn = authum_json_object_get_i32(body, "asn", -1);
    out->block = authum_json_object_get_i32(body, "block", 0);

    authum_logger_info(gatekeeper_log(), "iphub ok ip=%s code=%s asn=%d block=%d isp=%s",
                       out->ip, out->code, (int)out->asn, (int)out->block, out->isp);
    return authum_bool_true;
}
