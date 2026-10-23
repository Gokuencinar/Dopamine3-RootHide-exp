"""RootHide fork regression: per-process initialization must not be root-only.

Source and pinned bootstrap checks; not evidence of execution on an iPhone.
"""
import subprocess
from pathlib import Path
import unittest
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PORT = ROOT / 'BaseBin/systemhook/src/roothider_port.c'


class GlobalRoothideInitialization(unittest.TestCase):
    def test_actual_initializer_native_success_failure_and_confinement(self):
        cc = shutil.which('gcc') or shutil.which('clang') or shutil.which('cc')
        if not cc:
            self.skipTest('Host compiler unavailable')
        source = PORT.read_text(encoding='utf-8')
        actual = 'static int rh3_load_rooted_init(' + source.split(
            'static int rh3_load_rooted_init(', 1)[1].split(
            'static int rh3_load_rooted_patch(', 1)[0]
        harness = r'''
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include "roothide_trust_policy.h"
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
static const char root[] = "/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF";
static const char library[] = "/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/usr/lib/roothideinit.dylib";
static int scenario, opened;
static int fake_lstat(const char *p, struct stat *st) {
    if (strcmp(p,library) || scenario==1) {errno=ENOENT;return -1;}
    memset(st,0,sizeof(*st));
    st->st_mode = (scenario==2 ? S_IFLNK : S_IFREG) | (scenario==3 ? 0775 : 0755);
    st->st_uid = scenario==4 ? 501 : 0;
    st->st_nlink = scenario==5 ? 2 : 1;
    st->st_size = scenario==6 ? 0 : 128;
    return 0;
}
static char *fake_realpath(const char *p,char *out) {
    if (scenario==7) return NULL;
    if (scenario==8 && !strcmp(p,library)) p="/outside/lib.dylib";
    strcpy(out,p);return out;
}
static bool fake_macho(const char *p) {return scenario!=9 && !strcmp(p,library);}
static void *fake_dlopen(const char *p,int mode) {
    if (strcmp(p,library) || (mode & RTLD_NOW)!=RTLD_NOW) return NULL;
    opened++;return scenario==10 ? NULL : (void *)1;
}
#define JBROOT_PATH(path) (!strcmp(path,"/usr/lib/roothideinit.dylib") ? library : NULL)
#define lstat fake_lstat
#define realpath fake_realpath
#define rh3_trust_looks_like_macho fake_macho
#define dlopen fake_dlopen
''' + actual + r'''
int main(void) {
    scenario=0;opened=0;
    if (rh3_load_rooted_init(root)!=0 || opened!=1) return 1;
    for (scenario=1;scenario<=9;scenario++) {
        opened=0;
        if (rh3_load_rooted_init(root)==0 || opened) return 10+scenario;
    }
    scenario=10;opened=0;
    if (rh3_load_rooted_init(root)!=EIO || opened!=1) return 25;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            test_file = Path(d) / 'roothide_init_preflight.c'
            executable = Path(d) / 'runtime_init_probe.exe'
            test_file.write_text(harness, encoding='utf-8')
            build = subprocess.run([cc, '-std=c11', '-I', str(PORT.parent / 'common'),
                                    str(test_file), '-o', str(executable)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(executable)], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_pinned_bootstrap_actually_carries_the_initializer(self):
        asset = ROOT / 'Application/Dopamine/Resources/roothide_bootstrap_1900.tar.zst'
        result = subprocess.run(['tar', '-tf', str(asset)], text=True, capture_output=True, timeout=30)
        if result.returncode:
            self.skipTest('system tar cannot inspect the pinned zstd archive')
        self.assertIn('./usr/lib/roothideinit.dylib', result.stdout)

    def test_init_is_not_restricted_to_executables_inside_jbroot(self):
        src = PORT.read_text()
        routine = src.split('int roothide_prepare_checked_in_process(', 1)[1].split('void roothide_prepare_process(', 1)[0]
        # The constructor has already authenticated the process check-in
        # before calling this routine. Re-querying launchd here can fail
        # while services are coming up, silently suppressing roothideinit.
        self.assertNotIn('jbclient_roothide_jailbroken()', routine)
        self.assertIn('systemhook_is_roothide_root_path(root)', routine)
        self.assertIn('rh3_load_rooted_init(root)', routine)
        self.assertNotIn('root_contains_executable(', routine)
        executable = src.split('void roothide_prepare_process(', 1)[1].split('int roothide_trust_injected_libraries(', 1)[0]
        self.assertIn('root_contains_executable(root, executable)', executable)
        self.assertIn('roothide_redirect_home(root)', executable)
        self.assertNotIn('rh3_load_rooted_init(root)', executable)

    def test_load_is_limited_to_verified_signed_root_owned_file(self):
        src = PORT.read_text()
        routine = src.split('static int rh3_load_rooted_init(', 1)[1].split('int roothide_prepare_checked_in_process(', 1)[0]
        self.assertIn('lstat(', routine)
        self.assertIn('S_ISREG(', routine)
        self.assertIn('st.st_uid != 0', routine)
        self.assertIn('st.st_mode & 0022', routine)
        self.assertIn('realpath(', routine)
        self.assertIn('rh3_trust_is_active_root_child(', routine)
        self.assertIn('dlopen(', routine)
        self.assertIn('RTLD_NOW', routine)
        self.assertIn('rh3_trust_looks_like_macho(init)', routine)
        self.assertIn('return dlopen(init, RTLD_NOW) ? 0 : EIO;', routine)

    def test_init_failure_stops_patch_and_tweak_loader_not_process(self):
        src = (ROOT / 'BaseBin/systemhook/src/main.c').read_text()
        constructor = src.split('__attribute__((constructor)) static void initializer(', 1)[1]
        self.assertIn('int rh3InitStatus = roothide_prepare_checked_in_process(JB_RootPath);', constructor)
        self.assertIn('if (rh3InitStatus != 0) return;', constructor)
        self.assertLess(constructor.index('if (rh3InitStatus != 0) return;'),
                        constructor.index('roothide_prepare_process('))
        self.assertLess(constructor.index('if (rh3InitStatus != 0) return;'),
                        constructor.index('should_enable_tweaks()'))

    def test_systemhook_initialization_calls_per_process_init_after_checkin(self):
        src = (ROOT / 'BaseBin/systemhook/src/main.c').read_text()
        ctor = src.split('__attribute__((constructor)) static void initializer', 1)[1]
        self.assertLess(ctor.index('parse_dyldhook_jbinfo'), ctor.index('roothide_prepare_checked_in_process('))
        self.assertLess(ctor.index('jbclient_process_checkin('), ctor.index('roothide_prepare_checked_in_process('))
        self.assertIn('else {', ctor.split('jbclient_process_checkin(', 1)[1].split('roothide_prepare_checked_in_process(', 1)[0])
        # The donor loads roothideinit before resolving an executable path.
        # xpcproxy and shortly-lived services may not resolve a realpath.
        self.assertLess(ctor.index('roothide_prepare_checked_in_process('), ctor.index('if (load_executable_path() == 0)'))
        self.assertLess(ctor.index('roothide_prepare_checked_in_process('), ctor.index('roothide_prepare_process('))
        self.assertLess(ctor.index('roothide_prepare_process('), ctor.index('should_enable_tweaks()'))


if __name__ == '__main__':
    unittest.main()
