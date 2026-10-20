"""Userspace-reboot jailbreakd diagnostic and suspended-child safety contracts.

These are not substitute for a physical SpringBoard/LaunchServices test.
"""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPAWNER = (ROOT/'BaseBin/libjailbreak/src/roothider/jailbreakd.c').read_text(encoding='utf-8')
DAEMON = (ROOT/'BaseBin/jailbreakd/src/main.m').read_text(encoding='utf-8')
COMMON = (ROOT/'BaseBin/libjailbreak/src/roothider/common.m').read_text(encoding='utf-8')


class JailbreakdRespawn(unittest.TestCase):
    def test_boot_log_follows_daemon_through_both_generations(self):
        spawned = SPAWNER.split('int spawnJailbreakd()', 1)[1].split('int initJailbreakd(', 1)[0]
        self.assertIn('RH3_BOOT_LOG_PATH=%s', spawned)
        self.assertIn('RH3_BOOT_LOG_DEV=%s', spawned)
        self.assertIn('RH3_BOOT_LOG_INO=%s', spawned)
        self.assertIn('"RESPAWN_REQUIRED=1"', spawned)
        self.assertIn('index ? daemonEnv : NULL', spawned)
        self.assertIn('#include <libjailbreak/roothide_bootlog.h>', DAEMON)
        self.assertIn('posix_spawn(&pid, selfPath, NULL, &attr, argv, environ)', DAEMON)
        self.assertLess(DAEMON.index('unsetenv("RESPAWN_REQUIRED")'),
                        DAEMON.index('posix_spawn(&pid, selfPath'))

    def test_respawn_diagnostics_and_no_unpatched_child_resume(self):
        self.assertIn('jailbreakd: process entered main', DAEMON)
        self.assertIn('jailbreakd: primitive initialization completed', DAEMON)
        self.assertIn('jailbreakd: userspace reboot respawn branch entered', DAEMON)
        self.assertIn('jailbreakd: suspended replacement spawned', DAEMON)
        self.assertIn('jailbreakd: replacement patch completed', DAEMON)
        self.assertIn('jailbreakd: authenticated checkin starting', DAEMON)
        self.assertIn('jailbreakd: authenticated checkin failed', DAEMON)
        self.assertIn('jailbreakd: XPC receive source active', DAEMON)
        self.assertLess(DAEMON.index('int patchResult = unrestrict('),
                        DAEMON.index('if(dyld_patch_enabled())'))
        self.assertLess(DAEMON.index('if(patchResult != 0)'),
                        DAEMON.index('kill(pid, SIGCONT)'))
        self.assertIn('waitpid(pid, NULL, WNOHANG)', DAEMON)
        self.assertNotIn('waitpid(pid, NULL, 0)', DAEMON)

    def test_unrestrict_is_bounded_and_never_calls_patch_after_timeout(self):
        helper = COMMON.split('int unrestrict(pid_t pid,', 1)[1].split('bool process_force_dyld_patch', 1)[0]
        self.assertIn('attempt < 1000', helper)
        self.assertNotIn('while(true)', helper)
        self.assertIn('return -ETIMEDOUT', helper)
        self.assertLess(helper.index('return -ETIMEDOUT'), helper.index('callback(pid)'))
        self.assertLess(helper.index('callback(pid)'), helper.index('kill(pid, SIGCONT)'))

    @unittest.skipIf(sys.platform == 'win32', 'host C execution on macOS/Linux only')
    def test_native_bounded_wait_and_successful_patch(self):
        cc = shutil.which('clang') or shutil.which('cc')
        if not cc:
            self.skipTest('No C compiler')
        section = COMMON.split('int unrestrict(pid_t pid,', 1)[1].split('bool process_force_dyld_patch', 1)[0]
        function = 'int unrestrict(pid_t pid,' + section
        harness = r'''
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#define SIGCONT 18
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)
static int paused_after = -1,checks,patched,resumed;
static int proc_paused(pid_t pid, bool *paused) {
    checks++;
    *paused = paused_after >= 0 && checks >= paused_after;
    return 0;
}
static int usleep(unsigned int micros) { (void)micros;return 0; }
static int kill(pid_t pid,int signal) { resumed++;return 0; }
static char *proc_get_path(pid_t pid, char *buf) { return (char*)"mock"; }
static int patch(pid_t pid) { patched++; return 0; }
''' + function + r'''
int main(void) {
    if (unrestrict(10, patch, true) != -ETIMEDOUT) return 1;
    if (checks != 1000 || patched || resumed) return 2;
    checks = patched = resumed = 0; paused_after = 3;
    if (unrestrict(11, patch, true)) return 3;
    if (checks != 3 || patched != 1 || resumed != 1) return 4;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            c = Path(d)/'respawn.c'
            exe = Path(d)/'respawn'
            c.write_text(harness, encoding='utf-8')
            build = subprocess.run([cc, '-std=c11', '-Werror', str(c), '-o', str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(exe)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
