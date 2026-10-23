"""Regression contracts: never hand clients an unserviced RootHide daemon port."""

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
JBD = (ROOT / 'BaseBin/libjailbreak/src/roothider/jailbreakd.c').read_text(encoding='utf-8')
CLIENT = (ROOT / 'BaseBin/libjailbreak/src/jbclient_roothide.c').read_text(encoding='utf-8')
HDR = (ROOT / 'BaseBin/libjailbreak/src/roothider/jailbreakd.h').read_text(encoding='utf-8')
DOMAIN = (ROOT / 'BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c').read_text(encoding='utf-8')
MAIN = (ROOT / 'BaseBin/launchdhook/src/main.m').read_text(encoding='utf-8')


class JailbreakdCheckin(unittest.TestCase):
    def test_every_daemon_client_must_use_authenticated_launchd_lookup(self):
        # On r188 the old HOST_LAUNCHCTL_PORT path could expose a valid send
        # right before jailbreakd received its receive right or checked in.
        # xpc_pipe_routine would then wait for a daemon that cannot respond.
        client = JBD.split('mach_port_t jailbreakdClientPort()', 1)[1].split(
            'xpc_object_t jailbreakdXpcRequest(', 1)[0]
        self.assertIn('if (!jailbreakd_has_checked_in()) return MACH_PORT_NULL;', client)
        self.assertIn('port = jbclient_jailbreakd_lookup();', client)
        self.assertNotIn('jailbreakdClientPortFastGet()', client)
        self.assertNotIn('host_get_special_port(', JBD)
        self.assertNotIn('host_set_special_port(', JBD)

    def test_clients_cannot_get_unserviced_receive_port(self):
        lookup = DOMAIN.split('static int roothide_jailbreakd_lookup(', 1)[1].split(
            'static int roothide_jailbreakd_checkin(', 1)[0]
        self.assertIn('!jailbreakd_has_checked_in()', lookup)
        self.assertLess(lookup.index('!jailbreakd_has_checked_in()'), lookup.index('jailbreakdClientPort()'))
        self.assertIn('return -1;', lookup)
        self.assertIn('xpc_mach_send_create(port)', lookup)
        self.assertIn('jailbreakd_has_checked_in(void)', HDR)
        self.assertIn('jailbreakd_mark_checked_in(pid_t pid)', HDR)
        self.assertIn('return jailbreakd_is_ready() && __jailbreakd_checked_in_pid > 1;', JBD)
        self.assertIn('__jailbreakd_checked_in_pid = 0;', JBD)

    def test_checkin_authenticated_before_advertising_and_old_child_not_waited_on(self):
        checkin = DOMAIN.split('static int roothide_jailbreakd_checkin(', 1)[1].split(
            'static int roothide_dyld_patch_enabled(', 1)[0]
        self.assertLess(checkin.index('audit_token_to_euid'), checkin.index('jailbreakd_mark_checked_in(pid)'))
        self.assertLess(checkin.index('strcmp(executableRealPath, expectedRealPath)'),
                        checkin.index('jailbreakd_mark_checked_in(pid)'))
        self.assertLess(checkin.index('xpc_mach_recv_create(port)'),
                        checkin.index('jailbreakd_mark_checked_in(pid)'))
        self.assertIn('RootHide jailbreakd authenticated checkin completed', checkin)
        prior = JBD.split('void setJailbreakdProcess(pid_t pid)', 1)[1].split('int spawnJailbreakd()', 1)[0]
        self.assertIn('waitpid(oldpid, NULL, WNOHANG)', prior)
        self.assertNotIn('waitpid(oldpid, NULL, 0)', prior)
        self.assertNotIn('kill(oldpid', prior)
        self.assertIn('RootHide daemon spawned; authenticated checkin pending', MAIN)
        self.assertNotIn('"RootHide daemon ready"', MAIN)

    def test_trace_disambiguates_daemon_lookup_from_request_without_bypassing_patch(self):
        helper = (ROOT / 'BaseBin/libjailbreak/src/roothider/common.m').read_text(encoding='utf-8')
        lifecycle = CLIENT.split('static int roothide_lifecycle_request_traced(', 1)[1].split(
            'static int roothide_lifecycle_request(', 1)[0]
        self.assertIn('"jailbreakd lookup entering"', lifecycle)
        self.assertIn('"jailbreakd lookup returned"', lifecycle)
        self.assertIn('"jailbreakd request entering"', lifecycle)
        self.assertIn('"jailbreakd request returned"', lifecycle)
        self.assertLess(lifecycle.index('jbclient_jailbreakd_lookup()'), lifecycle.index('xpc_pipe_routine('))
        self.assertIn('jbclient_roothide_patch_child_traced(pid, should_resume, callback, context)', helper)
        self.assertIn('jbclient_roothide_patch_child(pid, should_resume)', helper)
        self.assertIn('if(patched != 0)', helper)
        self.assertNotIn('posix_spawn(pidp, path, fap, NULL', helper)

    @unittest.skipIf(sys.platform == 'win32', 'C runtime check on macOS / Linux CI')
    def test_checkin_gate_native(self):
        cc = shutil.which('cc') or shutil.which('clang')
        if cc is None:
            self.skipTest('No C compiler')
        start = JBD.index('bool jailbreakd_is_ready(void)')
        end = JBD.index('\nint registerServerPort()', start)
        functions = JBD[start:end]
        program = r'''
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/types.h>
#define MACH_PORT_VALID(x) ((x) > 0)
static pid_t real_pid=1;
static pid_t getpid(void) { return real_pid; }
static bool __jailbreakd_initialized=false;
static _Atomic(pid_t) __jailbreakd_checked_in_pid=0;
static int gJailbreakdPort=0;
''' + functions + r'''
int main(void) {
    if (jailbreakd_has_checked_in()) return 1;
    __jailbreakd_initialized=true; gJailbreakdPort=123;
    if (!jailbreakd_is_ready() || jailbreakd_has_checked_in()) return 2;
    jailbreakd_mark_checked_in(90);
    if (!jailbreakd_has_checked_in()) return 3;
    real_pid=90;
    if (jailbreakd_has_checked_in()) return 4;
    jailbreakd_mark_checked_in(91);
    real_pid=1;
    if (!jailbreakd_has_checked_in()) return 5;
    __jailbreakd_checked_in_pid=0;
    if (jailbreakd_has_checked_in()) return 6;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'gate.c'
            exe = Path(temp) / 'gate'
            path.write_text(program, encoding='utf-8')
            build = subprocess.run([cc, '-std=c11', str(path), '-o', str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            proc = subprocess.run([str(exe)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == '__main__':
    unittest.main()
