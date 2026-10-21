#ifndef GATEKEEPER_RESOLVE_H
#define GATEKEEPER_RESOLVE_H

#include <authum/bool.h>
#include <authum/event/client.h>
#include <authum/event/result.h>
#include <authum/ptr.h>

authum_bool_t
gatekeeper_resolve_start(void);
void
gatekeeper_resolve_stop(void);

authum_event_result_t
gatekeeper_on_client_connect(const authum_char_t *name, authum_ptr payload, authum_ptr user);
authum_event_result_t
gatekeeper_on_client_put_in_server(const authum_char_t *name, authum_ptr payload, authum_ptr user);
authum_event_result_t
gatekeeper_on_client_disconnect(const authum_char_t *name, authum_ptr payload, authum_ptr user);

#endif /* GATEKEEPER_RESOLVE_H */
