#ifndef GATEKEEPER_STEAM_GUARD_H
#define GATEKEEPER_STEAM_GUARD_H

#include <authum/bool.h>
#include <authum/char.h>

#include <gatekeeper/iphub/data.h>

/**
 * Steam-session antifraud (stolen / shared real tickets).
 * Remembers ASN(+country) per steamid; kicks when a new ASN exceeds the budget
 * or (optional) country never seen for that id.
 */

/** STEAM_/VALVE_ auth ids that are not LAN/PENDING/BOT/HLTV. */
authum_bool_t
gatekeeper_steam_guard_applicable(const authum_char_t *auth_id);

/**
 * @return true = allow. On allow, records/touches the session row when data is known.
 * Whitelist (filter) is checked by the caller before this when desired.
 */
authum_bool_t
gatekeeper_steam_guard_allow(const authum_char_t *auth_id, const gatekeeper_iphub_data_t *data);

#endif /* GATEKEEPER_STEAM_GUARD_H */
