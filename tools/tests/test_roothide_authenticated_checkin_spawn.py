"""An authenticated dyld/process check-in must carry to later spawn hooks.

The check-in's RootHide root is fixed for a process lifetime. Re-querying the
launchd domain on every spawn can fail during daemon startup and silently
disable preparation. PID1 must never inherit an authenticated client state.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "BaseBin/systemhook/src/common/common.c"
MAIN = ROOT / "BaseBin/systemhook/src/main.c"


class AuthenticatedCheckinSpawn(unittest.TestCase):
    def test_source_scopes_cached_checkin_to_verified_root_and_all_spawn_paths(self):
        common = COMMON.read_text(encoding="utf-8")
        main = MAIN.read_text(encoding="utf-8")
        cache = common.split('static _Atomic bool gRh3RootCheckedIn', 1)[1].split(
            '// RootHide\'s jbrand stores', 1)[0]
        self.assertIn('getpid() != 1', cache)
        self.assertIn('systemhook_is_roothide_root_path(root)', cache)
        self.assertIn('strcmp(root, gRh3CheckedInRoot)', cache)
        self.assertIn('atomic_store_explicit(&gRh3RootCheckedIn, true', cache)
        self.assertIn('atomic_load_explicit(&gRh3RootCheckedIn', cache)
        constructor = main.split('__attribute__((constructor)) static void initializer(', 1)[1]
        self.assertLess(constructor.index('jbclient_process_checkin('),
                        constructor.index('rh3_record_authenticated_root(JB_RootPath)'))
        self.assertLess(constructor.index('rh3_record_authenticated_root(JB_RootPath)'),
                        constructor.index('litehook_hook_function(__posix_spawn, __posix_spawn_hook)'))
        for source in [main, common]:
            self.assertIn('rh3_has_authenticated_root()', source)
            self.assertNotIn('jbclient_roothide_jailbroken()', source)

    def test_native_actual_cache_denies_pid1_old_roots_and_unchecked_processes(self):
        compiler = shutil.which('gcc') or shutil.which('clang') or shutil.which('cc')
        if not compiler:
            self.skipTest('Host C compiler unavailable')
        code = COMMON.read_text(encoding='utf-8')
        section = 'static _Atomic bool gRh3RootCheckedIn' + code.split(
            'static _Atomic bool gRh3RootCheckedIn', 1)[1].split(
            '// RootHide\'s jbrand stores', 1)[0]
        harness = r'''
#include <stdbool.h>
#include <string.h>
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
static int testPid = 40;
static const char *testRoot = "/var/containers/Bundle/Application/.jbroot-ABCDEF1111111150";
static int fake_pid(void) {return testPid;}
static char *get_jbroot(void) {return (char *)testRoot;}
static bool systemhook_is_roothide_root_path(const char *root) {
    return root && !strcmp(root,"/var/containers/Bundle/Application/.jbroot-ABCDEF1111111150");
}
#define getpid fake_pid
''' + section + r'''
int main(void) {
    const char *active = "/var/containers/Bundle/Application/.jbroot-ABCDEF1111111150";
    if (rh3_has_authenticated_root()) return 1;
    rh3_record_authenticated_root("/var/jb");
    if (rh3_has_authenticated_root()) return 2;
    rh3_record_authenticated_root(active);
    if (!rh3_has_authenticated_root()) return 3;
    // fork() inherits static memory but the new process never checked in.
    testPid = 41;
    if (rh3_has_authenticated_root()) return 7;
    testPid = 40;
    testPid = 1;
    if (rh3_has_authenticated_root()) return 4;
    testPid = 40;
    testRoot = "/private/var/containers/Bundle/Application/.jbroot-0000000000000000";
    if (rh3_has_authenticated_root()) return 5;
    testRoot = active;
    if (!rh3_has_authenticated_root()) return 6;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'checkin.c'
            exe = Path(tmp) / 'checkin_probe.exe'
            src.write_text(harness, encoding='utf-8')
            build = subprocess.run([compiler, '-std=c11', str(src), '-o', str(exe)],
                                   text=True, capture_output=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(exe)], text=True, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == '__main__':
    unittest.main()
