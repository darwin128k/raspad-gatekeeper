#ifndef GATEKEEPER_FILTER_H
#define GATEKEEPER_FILTER_H

#include <authum/bool.h>
#include <authum/char.h>

#include <gatekeeper/iphub/data.h>

/** true = allow connection. */
authum_bool_t gatekeeper_filter_allow(const gatekeeper_iphub_data_t *data,
				      const authum_char_t *auth_id);

#endif /* GATEKEEPER_FILTER_H */
