#ifndef GATEKEEPER_SQL_H
#define GATEKEEPER_SQL_H

#include <authum/bool.h>
#include <authum/char.h>

#include <gatekeeper/iphub/data.h>

authum_bool_t gatekeeper_sql_open(void);
void gatekeeper_sql_close(void);

/** Lookup by IP. Fills @p out; returns true when a row exists. */
authum_bool_t gatekeeper_sql_get_by_ip(const authum_char_t *ip, gatekeeper_iphub_data_t *out);

/** Insert IPHub row; sets out->id on success. */
authum_bool_t gatekeeper_sql_insert_ip(gatekeeper_iphub_data_t *row);

/** steamid → client row id, or -1. Creates row linked to @p log_id when missing. */
authum_i32_t gatekeeper_sql_ensure_client(authum_i32_t log_id, const authum_char_t *steamid);

#endif /* GATEKEEPER_SQL_H */
