#include <gatekeeper/iphub/data.h>

#include <authum/null.h>
#include <string.h>

void
gatekeeper_iphub_data_clear(gatekeeper_iphub_data_t *self)
{
    if (authum_null_eq(self))
    {
        return;
    }
    memset(self, 0, sizeof *self);
    self->id = -1;
    self->asn = -1;
}
