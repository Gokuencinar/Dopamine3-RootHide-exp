#include <libjailbreak/libjailbreak.h>
#include <mach-o/dyld.h>
#include <xpc/xpc.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sandbox.h>
#include <substrate.h>
#include <libjailbreak/jbserver.h>
#include <libjailbreak/roothider.h>
#include <litehook.h>

// RootHide's reply transformations live in libjailbreak, while the launchd
// receiver and hook installation belong to launchdhook.
extern bool roothide_prepare_xpc_filters(void);
extern bool roothide_filter_xpc_message(xpc_object_t xmsg);
extern xpc_object_t (*orig_xpc_dictionary_create_reply)(xpc_object_t original);
extern xpc_object_t new_xpc_dictionary_create_reply(xpc_object_t original);
extern int (*orig_xpc_pipe_routine_reply)(xpc_object_t reply);
extern int new_xpc_pipe_routine_reply(xpc_object_t reply);

static bool gRootHideXPCFiltersReady = false;

mach_msg_header_t* dispatch_mach_msg_get_msg(void *message, size_t *_Nullable size_ptr);
int jbserver_received_mach_message(audit_token_t *auditToken, struct jbserver_mach_msg *jbsMachMsg);
int jbserver_received_complex_mach_message(audit_token_t *auditToken, uint64_t action, struct jbserver_mach_complex_msg *jbsMachMsg);

int xpc_receive_mach_msg(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut);
int (*xpc_receive_mach_msg_orig)(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut);
int xpc_receive_mach_msg_hook(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut)
{
	size_t msgBufSize = 0;
    struct jbserver_mach_msg *jbsMachMsg = (struct jbserver_mach_msg *)dispatch_mach_msg_get_msg(msg, &msgBufSize);
	bool wasProcessed = false;
    if (jbsMachMsg != NULL && msgBufSize >= sizeof(mach_msg_header_t)) {
        size_t msgSize = jbsMachMsg->hdr.msgh_size;
        if (msgSize <= msgBufSize && msgSize >= sizeof(struct jbserver_mach_msg) && jbsMachMsg->magic == JBSERVER_MACH_MAGIC) {
			mach_msg_context_trailer_t *trailer = (mach_msg_context_trailer_t *)((uint8_t *)jbsMachMsg + round_msg(jbsMachMsg->hdr.msgh_size));
            jbserver_received_mach_message(&trailer->msgh_audit, jbsMachMsg);
			wasProcessed = true;
            // Pass the message to xpc_receive_mach_msg anyway, it will get rid of it for us
        }
    }
	// Not needed, since we don't have any complex messages at the moment
	/*struct jbserver_mach_complex_msg *jbsComplexMachMsg = (struct jbserver_mach_complex_msg *)jbsMachMsg;
	if (!wasProcessed && jbsComplexMachMsg != NULL && msgBufSize >= sizeof(struct jbserver_mach_complex_msg)) {
		// Warning: Witchcraft incoming
		size_t msgSize = jbsComplexMachMsg->hdr.msgh_size;
		if (jbsComplexMachMsg->hdr.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
			uintptr_t magicOff = sizeof(struct jbserver_mach_complex_msg) + (jbsComplexMachMsg->body.msgh_descriptor_count * sizeof(mach_msg_port_descriptor_t));
			uintptr_t actionOff = magicOff + sizeof(uint64_t);
			if (msgSize >= (actionOff + sizeof(uint64_t))) {
				uint64_t magic = *(uint64_t *)(((uintptr_t)jbsComplexMachMsg) + magicOff);
				if (magic == JBSERVER_MACH_MAGIC) {
					uint64_t action = *(uint64_t *)(((uintptr_t)jbsComplexMachMsg) + actionOff);
					mach_msg_context_trailer_t *trailer = (mach_msg_context_trailer_t *)((uint8_t *)jbsComplexMachMsg + round_msg(jbsComplexMachMsg->hdr.msgh_size));
					jbserver_received_complex_mach_message(&trailer->msgh_audit, action, jbsComplexMachMsg);
					wasProcessed = true;
            		// Pass the message to xpc_receive_mach_msg anyway, it will get rid of it for us
				}
			}
		}
	}*/

	int r = xpc_receive_mach_msg_orig(msg, a2, a3, a4, xOut);
	if (!wasProcessed && r == 0 && xOut && *xOut) {
		if (gRootHideXPCFiltersReady && xpc_get_type(*xOut) == XPC_TYPE_DICTIONARY) {
			// The stock jbserver rejects launchd's ordinary XPC requests. Apply
			// RootHide's request filter before dispatching them to launchd.
			(void)roothide_filter_xpc_message(*xOut);
		}
		if (jbserver_received_xpc_message(&gGlobalServer, *xOut) == 0) {
			// Returning non null here makes launchd disregard this message
			// For jailbreak messages we have the logic to handle them
			xpc_release(*xOut);
			return 22;
		}
	}
	return r;
}

void initXPCHooks(void)
{
	xpc_receive_mach_msg_orig = xpc_receive_mach_msg;
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, xpc_receive_mach_msg, xpc_receive_mach_msg_hook, NULL);

	// This initializer is also used by stock Dopamine. No RootHide policy or
	// response interception must be installed for its ordinary preboot root.
	if (!roothide_is_active() || !roothide_prepare_xpc_filters()) return;

	MSHookFunction((void *)&xpc_dictionary_create_reply,
	               (void *)&new_xpc_dictionary_create_reply,
	               (void **)&orig_xpc_dictionary_create_reply);
	MSHookFunction((void *)&xpc_pipe_routine_reply,
	               (void *)&new_xpc_pipe_routine_reply,
	               (void **)&orig_xpc_pipe_routine_reply);
	if (!orig_xpc_dictionary_create_reply || !orig_xpc_pipe_routine_reply) {
		JBLogError("RootHide XPC reply hooks missing original implementation");
		return;
	}
	gRootHideXPCFiltersReady = true;
}
