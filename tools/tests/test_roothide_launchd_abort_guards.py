"""Static guards against turning optional RootHide IPC failures into PID 1 panics.

These source contracts do not prove that a device can safely inject launchd.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
MAIN = (ROOT / "BaseBin/launchdhook/src/main.m").read_text(encoding="utf-8")
JBD = (ROOT / "BaseBin/libjailbreak/src/roothider/jailbreakd.c").read_text(encoding="utf-8")
SPAWN_H = (ROOT / "BaseBin/launchdhook/src/spawn_hook.h").read_text(encoding="utf-8")
SPAWN_C = (ROOT / "BaseBin/launchdhook/src/spawn_hook.c").read_text(encoding="utf-8")
BOOMERANG = (ROOT / "BaseBin/launchdhook/src/boomerang.c").read_text(encoding="utf-8")


class LaunchdAbortGuards(unittest.TestCase):
    def test_roothide_boomerang_failure_returns_before_stock_abort(self):
        block = MAIN.split('int err = boomerang_recoverPrimitives(firstLoad, true);', 1)[1].split('if (roothide_is_active()) launchdhookFirstLoad', 1)[0]
        self.assertRegex(block, r'if\s*\(roothide_launchdhook_origin_verified\(\)\)\s*\{[^}]*unsetenv\("DYLD_INSERT_LIBRARIES"\);[^}]*return;')
        self.assertLess(block.index('if (roothide_launchdhook_origin_verified())'), block.index('abort_with_reason'))
        self.assertIn('abort_with_reason(7, 1, msg, 0);', block)

    def test_origin_guard_is_available_before_boomerang_restores_brand(self):
        self.assertIn('bool roothide_launchdhook_origin_verified(void);', SPAWN_H)
        self.assertIn('bool roothide_launchdhook_origin_verified(void)', SPAWN_C)
        self.assertIn('systemhook_is_roothide_root_path(root)', SPAWN_C)
        self.assertIn('dladdr((const void *)&roothide_launchdhook_origin_verified', SPAWN_C)

    def test_failed_roothide_primitive_handoff_does_not_signal_success(self):
        self.assertIn('#include "spawn_hook.h"', BOOMERANG)
        self.assertIn('int primitiveStatus = jbclient_initialize_primitives_internal(physrwPTE);', BOOMERANG)
        guard = 'if (primitiveStatus != 0 && roothide_launchdhook_origin_verified()) return -3;'
        self.assertIn(guard, BOOMERANG)
        self.assertLess(BOOMERANG.index(guard), BOOMERANG.index('jbclient_boomerang_done();'))

    def test_dead_jailbreakd_port_never_aborts_pid1(self):
        block = JBD.split('mach_port_t reactiveJailbreakdPort()', 1)[1].split('mach_port_t jailbreakdServerPort()', 1)[0]
        self.assertNotRegex(block, r'\babort\s*\(')
        self.assertIn('return MACH_PORT_NULL;', block)
        self.assertIn('#ifndef ENABLE_LOGS', block)

    def test_jailbreakd_bootstrap_dispatch_preserves_nonfatal_rejection(self):
        block = JBD.split('int spawnJailbreakd()', 1)[1].split('int initJailbreakd(', 1)[0]
        self.assertNotRegex(block, r'\babort\s*\(')
        self.assertIn('RH3DispatchBootstrapMessage(gJailbreakdBootstrapServer, xdict)', block)
        self.assertIn('initJailbreakd(firstLoad, &gGlobalServer)', MAIN)
        self.assertIn('xpc_release(xdict);', block)


if __name__ == '__main__':
    unittest.main()
