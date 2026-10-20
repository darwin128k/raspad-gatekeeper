#include <gatekeeper/bridge.h>

#include <authum/client.h>

AUTHUM_MODULE_EXPORT const authum_module_api_t authum_module_api = {
	.start = gatekeeper_authum_start,
	.stop = gatekeeper_authum_stop,
};
