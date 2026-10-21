#ifndef GATEKEEPER_BRIDGE_H
#define GATEKEEPER_BRIDGE_H

#include <authum/client.h>

authum_bool_t
gatekeeper_authum_start(authum_host_t *host);
void
gatekeeper_authum_stop(void);

#endif /* GATEKEEPER_BRIDGE_H */
