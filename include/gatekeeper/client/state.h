#ifndef GATEKEEPER_CLIENT_STATE_H
#define GATEKEEPER_CLIENT_STATE_H

#include <authum/bool.h>
#include <authum/char.h>
#include <authum/size.h>

#include <gatekeeper/iphub/data.h>

enum
{
    gatekeeper_max_players = 32
};

struct gatekeeper_client_slot
{
    authum_bool_t used;
    authum_i32_t userid;
    authum_u32_t generation;
    authum_bool_t pending;
    authum_char_t ip[gatekeeper_ip_size];
    authum_i32_t client_row_id;
    authum_char_t auth_id[64];
    gatekeeper_iphub_data_t iphub;
};
typedef struct gatekeeper_client_slot gatekeeper_client_slot_t;

authum_bool_t
gatekeeper_client_state_start(void);
void
gatekeeper_client_state_stop(void);

gatekeeper_client_slot_t *
gatekeeper_client_slot(authum_i32_t index);
void
gatekeeper_client_slot_clear(authum_i32_t index);

#endif /* GATEKEEPER_CLIENT_STATE_H */
