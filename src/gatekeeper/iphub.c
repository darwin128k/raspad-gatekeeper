#include <gatekeeper/iphub.h>

#include <gatekeeper/config.h>
#include <gatekeeper/host.h>

#include <authum/cstr.h>
#include <authum/json.h>
#include <authum/null.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

authum_bool_t
gatekeeper_iphub_lookup(const authum_char_t *ip, gatekeeper_iphub_data_t *out)
{
	struct hostent *he;
	struct sockaddr_in addr;
	int fd = -1;
	authum_char_t req[512];
	authum_char_t buf[4096];
	authum_usize_t total = 0u;
	ssize_t n;
	const authum_char_t *body;
	struct timeval tv;

	if (authum_null_eq(ip) || authum_null_eq(out) || g_gatekeeper_config.iphub_api_key[0] == '\0')
		return authum_bool_false;

	gatekeeper_iphub_data_clear(out);
	authum_cstr_copy(out->ip, sizeof out->ip, ip);

	he = gethostbyname("v2.api.iphub.info");
	if (authum_null_eq(he) || authum_null_eq(he->h_addr_list) || authum_null_eq(he->h_addr_list[0])) {
		authum_logger_error(&g_gatekeeper_logger, "iphub: DNS failed");
		return authum_bool_false;
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return authum_bool_false;

	tv.tv_sec = (time_t)(g_gatekeeper_config.iphub_timeout_ms / 1000);
	tv.tv_usec = (long)(g_gatekeeper_config.iphub_timeout_ms % 1000) * 1000L;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(80);
	memcpy(&addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);

	if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
		authum_logger_error(&g_gatekeeper_logger, "iphub: connect failed");
		close(fd);
		return authum_bool_false;
	}

	snprintf(req, sizeof req,
		 "GET /ip/%s HTTP/1.0\r\n"
		 "Host: v2.api.iphub.info\r\n"
		 "X-Key: %s\r\n"
		 "Connection: close\r\n"
		 "\r\n",
		 ip, g_gatekeeper_config.iphub_api_key);

	if (send(fd, req, strlen(req), 0) < 0) {
		close(fd);
		return authum_bool_false;
	}

	while (total + 1u < sizeof buf) {
		n = recv(fd, buf + total, sizeof buf - total - 1u, 0);
		if (n <= 0)
			break;
		total += (authum_usize_t)n;
	}
	close(fd);
	buf[total] = '\0';

	if (strstr(buf, "HTTP/1.0 200") == authum_null && strstr(buf, "HTTP/1.1 200") == authum_null) {
		authum_logger_error(&g_gatekeeper_logger, "iphub: bad HTTP status (ip=%s)", ip);
		return authum_bool_false;
	}

	body = strstr(buf, "\r\n\r\n");
	if (authum_null_eq(body)) {
		authum_logger_error(&g_gatekeeper_logger, "iphub: no body");
		return authum_bool_false;
	}
	body += 4;

	authum_json_object_get_cstr(body, "countryCode", out->code, sizeof out->code);
	authum_json_object_get_cstr(body, "countryName", out->name, sizeof out->name);
	authum_json_object_get_cstr(body, "isp", out->isp, sizeof out->isp);
	out->asn = authum_json_object_get_i32_or(body, "asn", -1);
	out->block = authum_json_object_get_i32_or(body, "block", 0);

	authum_logger_info(&g_gatekeeper_logger, "iphub ok ip=%s code=%s asn=%d block=%d isp=%s",
			   out->ip, out->code, (int)out->asn, (int)out->block, out->isp);
	return authum_bool_true;
}
