"""Source-level contracts for RootHide launchd XPC filtering.

These tests cover integration, fail-safe initialization and reply-hook ABI.
They cannot prove private XPC hook support on a real iOS device.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
RECEIVER = (ROOT / "BaseBin/launchdhook/src/xpc_hook.c").read_text(encoding="utf-8")
POLICY = (ROOT / "BaseBin/libjailbreak/src/roothider/xpc_hook.m").read_text(encoding="utf-8")
MAIN = (ROOT / "BaseBin/launchdhook/src/main.m").read_text(encoding="utf-8")


class RootHideXPCHookTests(unittest.TestCase):
    def test_stock_receiver_still_installed_before_roothide_gate(self):
        initializer = RECEIVER.split("void initXPCHooks(void)", 1)[1]
        self.assertIn("litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, xpc_receive_mach_msg", initializer)
        gate = "if (!roothide_is_active() || !roothide_prepare_xpc_filters()) return;"
        self.assertIn(gate, initializer)
        self.assertLess(initializer.index("litehook_rebind_symbol"), initializer.index(gate))
        self.assertLess(initializer.index(gate), initializer.index("MSHookFunction"))
        self.assertLess(initializer.index("MSHookFunction"), initializer.index("gRootHideXPCFiltersReady = true;"))
        self.assertIn("initXPCHooks();", MAIN)

    def test_dictionary_filter_runs_before_launchd_dispatch_only_when_ready(self):
        receiver = RECEIVER.split("int xpc_receive_mach_msg_hook(", 1)[1]
        self.assertIn("!wasProcessed && r == 0 && xOut && *xOut", receiver)
        self.assertIn("gRootHideXPCFiltersReady && xpc_get_type(*xOut) == XPC_TYPE_DICTIONARY", receiver)
        self.assertIn("roothide_filter_xpc_message(*xOut)", receiver)
        self.assertLess(receiver.index("roothide_filter_xpc_message(*xOut)"),
                        receiver.index("jbserver_received_xpc_message(&gGlobalServer, *xOut)"))

    def test_reply_abi_and_marker_are_preserved(self):
        for name, ret in (("xpc_dictionary_create_reply", "xpc_object_t"),
                          ("xpc_pipe_routine_reply", "int")):
            orig = rf"{ret}\s*\(\*orig_{name}\)\(xpc_object_t\s+\w+\)"
            wrapper = rf"{ret}\s+new_{name}\(xpc_object_t\s+\w+\)"
            self.assertRegex(POLICY, orig)
            self.assertRegex(POLICY, wrapper)
            self.assertRegex(RECEIVER, rf"MSHookFunction\(\(void \*\)&{name},")
        self.assertIn('xpc_dictionary_set_value(reply, "roothide-blacklisted-process-request", original)', POLICY)
        self.assertIn('xpc_dictionary_set_value(reply, "roothide-blacklisted-process-request", NULL)', POLICY)
        self.assertLess(POLICY.index('xpc_dictionary_set_value(reply, "roothide-blacklisted-process-request", NULL)'),
                        POLICY.index('return orig_xpc_pipe_routine_reply(reply);'))
        self.assertIn("if (!orig_xpc_pipe_routine_reply) return ENOSYS;", POLICY)

    def test_reply_request_survives_marker_removal(self):
        handler = POLICY.split("int new_xpc_pipe_routine_reply(xpc_object_t reply)", 1)[1].split(
            "#define RB2_USERREBOOT", 1
        )[0]
        removal = handler.index('xpc_dictionary_set_value(reply, "roothide-blacklisted-process-request", NULL)')
        read = handler.index('xpc_dictionary_get_audit_token(original, &clientToken)')
        routine = handler.index('xpc_dictionary_get_uint64(original, "routine")')
        subsystem = handler.index('xpc_dictionary_get_uint64(original, "subsystem")')
        self.assertLess(read, routine)
        self.assertLess(subsystem, removal)
        self.assertNotIn("xpc_retain(original)", handler)
        self.assertNotIn("xpc_release(original)", handler)

    def test_identifier_snapshot_is_safe_to_initialize(self):
        init = POLICY.split("bool roothide_prepare_xpc_filters(void)", 1)[1].split(
            "bool roothide_filter_xpc_message", 1
        )[0]
        self.assertIn("if (!roothide_is_active()) return false;", init)
        self.assertIn("if (!containers)", init)
        self.assertIn("return false;", init)
        self.assertIn('@"MCMMetadataIdentifier"', init)
        self.assertIn('@"iTunesMetadata.plist"', init)
        self.assertIn('@"_TrollStore"', init)
        self.assertIn('@"PlugIns"', init)
        self.assertIn('@"Extensions"', init)
        self.assertIn('@"SC_Info"', init)
        self.assertLess(init.index("NSMutableSet<NSString *> *identifiers ="),
                        init.index("StoredAppIdentifiers = identifiers;"))
        self.assertNotIn("abort()", init)

    def test_unknown_requests_are_not_crash_triggers(self):
        request = POLICY.split("bool roothide_handle_xpc_msg(xpc_object_t xmsg)", 1)[1]
        self.assertIn("if (!roothide_is_active() || !xmsg || xpc_get_type(xmsg) != XPC_TYPE_DICTIONARY)", request)
        self.assertNotIn('launchd_panic("consistency corruption")', request)
        self.assertRegex(request, re.compile(r"Unknown launchd routines are passed through unchanged\.\s*return false;"))

    def test_missing_hidden_root_does_not_abort_launchd(self):
        checker = POLICY.split("static bool check_path_in_jbroot(", 1)[1].split(
            "xpc_object_t (*orig_xpc_dictionary_create_reply)", 1
        )[0]
        self.assertNotIn("assert(", checker)
        self.assertIn("if (!resolved_jbroot || !real_path) return true;", checker)
        self.assertIn("== '\\0'", checker)

    def test_reply_marker_is_only_emitted_after_send_hook_is_ready(self):
        initializer = RECEIVER.split("void initXPCHooks(void)", 1)[1]
        self.assertLess(initializer.index("MSHookFunction((void *)&xpc_pipe_routine_reply"),
                        initializer.index("MSHookFunction((void *)&xpc_dictionary_create_reply"))
        self.assertLess(initializer.index("roothide_set_xpc_reply_hooks_ready(true);"),
                        initializer.index("gRootHideXPCFiltersReady = true;"))
        self.assertIn("if (!orig_xpc_pipe_routine_reply)", initializer)
        self.assertIn("return;", initializer.split("if (!orig_xpc_pipe_routine_reply)", 1)[1])
        create = POLICY.split("xpc_object_t new_xpc_dictionary_create_reply", 1)[1].split(
            "int (*orig_xpc_pipe_routine_reply)", 1
        )[0]
        self.assertIn("atomic_load_explicit(&gRootHideReplyHooksReady, memory_order_acquire)", create)
        self.assertLess(create.index("atomic_load_explicit("),
                        create.index('xpc_dictionary_set_value(reply, "roothide-blacklisted-process-request"'))


if __name__ == "__main__":
    unittest.main()
