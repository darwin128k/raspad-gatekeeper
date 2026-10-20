#ifndef GATEKEEPER_EVENT_RESOLVED_H
#define GATEKEEPER_EVENT_RESOLVED_H

#include <authum/char.h>
#include <authum/size.h>

#include <gatekeeper/iphub/data.h>

struct gatekeeper_event_resolved
{
    authum_usize_t size;
    authum_i32_t index;
    authum_i32_t userid;
    authum_char_t auth_id[64];
    gatekeeper_iphub_data_t iphub;
};
typedef struct gatekeeper_event_resolved gatekeeper_event_resolved_t;

#endif /* GATEKEEPER_EVENT_RESOLVED_H */
