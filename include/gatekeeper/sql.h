#ifndef GATEKEEPER_SQL_H
#define GATEKEEPER_SQL_H

#include <authum/bool.h>
#include <authum/char.h>
#include <authum/sql.h>

#include <gatekeeper/iphub/data.h>

void gatekeeper_sql_bind(authum_sql_t *db);
const authum_char_t *gatekeeper_sql_error(void);
authum_bool_t gatekeeper_sql_ensure_schema(void);

/** Lookup by IP. Fills @p out; returns true when a row exists. */
authum_bool_t
gatekeeper_sql_get_by_ip(const authum_char_t *ip, gatekeeper_iphub_data_t *out);

/** Insert IPHub row; sets out->id on success. */
authum_bool_t
gatekeeper_sql_insert_ip(gatekeeper_iphub_data_t *row);

/** steamid → client row id, or -1. Creates row linked to @p log_id when missing. */
authum_i32_t
gatekeeper_sql_ensure_client(authum_i32_t log_id, const authum_char_t *steamid);

/** Steam-session table: known ASN for steamid? */
authum_bool_t
gatekeeper_sql_session_has_asn(const authum_char_t *steamid, authum_i32_t asn);

/** Any prior session row with this country code for steamid? */
authum_bool_t
gatekeeper_sql_session_has_code(const authum_char_t *steamid, const authum_char_t *code);

/** Distinct ASN count for steamid. */
authum_i32_t
gatekeeper_sql_session_asn_count(const authum_char_t *steamid);

/** Insert or bump hits for (steamid, asn). */
authum_bool_t
gatekeeper_sql_session_touch(const authum_char_t *steamid, const gatekeeper_iphub_data_t *data);

#endif /* GATEKEEPER_SQL_H */
