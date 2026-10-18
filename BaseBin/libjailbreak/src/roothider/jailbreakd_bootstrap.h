#ifndef RH3_JAILBREAKD_BOOTSTRAP_H
#define RH3_JAILBREAKD_BOOTSTRAP_H
#include "../jbserver.h"

// Forward the received object itself: rebuilding a dictionary would lose the
// kernel-supplied audit token used by the existing domain permission checks.
static inline int RH3DispatchBootstrapMessage(struct jbserver_impl *server, xpc_object_t message)
{
    if (!server || !message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return -1;
    return jbserver_received_xpc_message(server, message);
}
#endif
