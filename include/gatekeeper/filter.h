#ifndef GATEKEEPER_FILTER_H
#define GATEKEEPER_FILTER_H

#include <authum/bool.h>
#include <authum/char.h>
#include <authum/size.h>

#include <gatekeeper/iphub/data.h>

enum gatekeeper_filter_result
{
    gatekeeper_filter_result_allow = 0,
    gatekeeper_filter_result_deny_country = 1,
    gatekeeper_filter_result_deny_block = 2
};
typedef enum gatekeeper_filter_result gatekeeper_filter_result_t;

authum_bool_t
gatekeeper_filter_whitelisted(const gatekeeper_iphub_data_t *data, const authum_char_t *auth_id);

/** Allow / deny with a concrete reason (country vs IPHub block). */
gatekeeper_filter_result_t
gatekeeper_filter_check(const gatekeeper_iphub_data_t *data, const authum_char_t *auth_id);

authum_bool_t
gatekeeper_filter_allow(const gatekeeper_iphub_data_t *data, const authum_char_t *auth_id);

/** Player-facing reject/kick text (uses filter_kick_reason + detail). */
void
gatekeeper_filter_format_reject(gatekeeper_filter_result_t result,
                                const gatekeeper_iphub_data_t *data, authum_char_t *buf,
                                authum_usize_t buf_size);

#endif /* GATEKEEPER_FILTER_H */
