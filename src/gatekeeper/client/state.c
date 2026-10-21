#include <gatekeeper/client/state.h>

#include <authum/null.h>
#include <string.h>

static gatekeeper_client_slot_t g_slots[gatekeeper_max_players + 1];

authum_bool_t
gatekeeper_client_state_start(void)
{
    authum_i32_t i;

    for (i = 0; i <= gatekeeper_max_players; ++i)
    {
        gatekeeper_client_slot_clear(i);
    }
    return authum_bool_true;
}

void
gatekeeper_client_state_stop(void)
{
    gatekeeper_client_state_start();
}

gatekeeper_client_slot_t *
gatekeeper_client_slot(authum_i32_t index)
{
    if (index < 1 || index > gatekeeper_max_players)
    {
        return authum_null;
    }
    return &g_slots[index];
}

void
gatekeeper_client_slot_clear(authum_i32_t index)
{
    gatekeeper_client_slot_t *slot = gatekeeper_client_slot(index);

    if (authum_null_eq(slot))
    {
        return;
    }
    memset(slot, 0, sizeof *slot);
    gatekeeper_iphub_data_clear(&slot->iphub);
    slot->client_row_id = -1;
}
