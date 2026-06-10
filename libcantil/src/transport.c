#include <stdlib.h>
#include "internal.h"

void cantil_transport_close(cantil_transport_t *t)
{
    if (!t)
        return;
    if (t->close)
        t->close(t);
    free(t);
}
