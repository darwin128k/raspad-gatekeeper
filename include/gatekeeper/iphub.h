#ifndef GATEKEEPER_IPHUB_H
#define GATEKEEPER_IPHUB_H

#include <authum/bool.h>
#include <authum/char.h>

#include <gatekeeper/iphub/data.h>

/**
 * Synchronous HTTP lookup (v2.api.iphub.info). Fills @p out except id.
 * Needs IphubApiKey in cfg.
 */
authum_bool_t
gatekeeper_iphub_lookup(const authum_char_t *ip, gatekeeper_iphub_data_t *out);

#endif /* GATEKEEPER_IPHUB_H */
