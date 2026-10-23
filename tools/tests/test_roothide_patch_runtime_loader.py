"""The optional RootHide patch runtime must load only from the active root."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PORT = ROOT / 'BaseBin/systemhook/src/roothider_port.c'


class RootHidePatchRuntimeLoader(unittest.TestCase):
    def test_staged_after_executable_only_not_global_checkin(self):
        src = PORT.read_text(encoding='utf-8')
        global_init = src.split('int roothide_prepare_checked_in_process(', 1)[1].split(
            'void roothide_prepare_process(', 1)[0]
        by_executable = src.split('void roothide_prepare_process(', 1)[1].split(
            'int roothide_prepare_patch_for_tweaks(', 1)[0]
        self.assertIn('rh3_load_rooted_init(root)', global_init)
        self.assertNotIn('rh3_load_rooted_patch(root)', global_init)
        self.assertIn('root_contains_executable(root, executable)', by_executable)
        self.assertIn('roothide_call_pathhook(root)', by_executable)
        self.assertNotIn('rh3_load_rooted_patch(root)', by_executable)
        self.assertIn('JBROOT_PATH("/usr/lib/roothidepatch.dylib")', src)
        loader = src.split('static int rh3_load_rooted_patch(', 1)[1].split(
            'int roothide_prepare_checked_in_process(', 1)[0]
        self.assertNotIn('jbclient_trust_library_recurse(', loader)
        self.assertIn('rh3_trust_looks_like_macho(patch)', loader)
        self.assertIn('S_ISLNK(compatStat.st_mode)', loader)
        self.assertIn('compatStat.st_uid != 0', loader)
        self.assertIn('return dlopen(patch, RTLD_NOW) ? 0 : EIO', loader)
        main = (ROOT / 'BaseBin/systemhook/src/main.c').read_text(encoding='utf-8')
        self.assertIn('roothide_prepare_process(', main)
        self.assertIn('bool rh3TweaksRequested = should_enable_tweaks();', main)
        self.assertIn('int rh3PatchStatus = rh3TweaksRequested ?', main)
        self.assertIn('roothide_prepare_patch_for_tweaks(JB_RootPath, gExecutablePath) : 0;', main)
        self.assertIn('if (rh3PatchStatus == 0 && rh3TweaksRequested)', main)
        routine = main.split('bool rh3TweaksRequested = should_enable_tweaks();', 1)[1]
        self.assertLess(routine.index('roothide_prepare_patch_for_tweaks('),
                        routine.index('dlopen(tweakLoaderPath, RTLD_NOW)'))
        stage = src.split('int roothide_prepare_patch_for_tweaks(', 1)[1].split(
            'int roothide_trust_injected_libraries(', 1)[0]
        self.assertIn('return rh3_load_rooted_patch(root);', stage)
        self.assertNotIn('root_contains_executable(', stage)
        self.assertIn('int64_t PLRequiredJIT(void)', main)
        self.assertIn('visibility("default")', main)

    def test_native_actual_loader_positive_and_adversarial_cases(self):
        cc = shutil.which('clang') or shutil.which('gcc') or shutil.which('cc')
        if not cc:
            self.skipTest('Host C compiler unavailable')
        src = PORT.read_text(encoding='utf-8')
        loader = 'static int rh3_load_rooted_patch(' + src.split(
            'static int rh3_load_rooted_patch(', 1)[1].split(
            'int roothide_prepare_checked_in_process(', 1)[0]
        test = r'''
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <dlfcn.h>
#include <errno.h>
#include "roothide_trust_policy.h"
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_ISLNK
#define S_ISLNK(mode) (((mode) & 0170000) == S_IFLNK)
#endif
static const char root[] = "/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF";
static const char patchPath[] = "/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/usr/lib/roothidepatch.dylib";
static const char compatPath[] = "/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/var/jb";
static int scenario, opened;
static bool systemhook_is_roothide_root_path(const char *p) { return p && strcmp(p, root) == 0; }
static int fake_lstat(const char *p, struct stat *st) {
    if (!strcmp(p, compatPath)) {
        if (scenario == 11) {errno = ENOENT;return -1;}
        memset(st,0,sizeof(*st));
        st->st_mode = (scenario == 12 ? S_IFREG : S_IFLNK) | 0755;
        st->st_uid = scenario == 14 ? 501 : 0;
        st->st_nlink = scenario == 15 ? 2 : 1;
        return 0;
    }
    if (strcmp(p, patchPath) || scenario == 5) {errno = ENOENT;return -1;}
    memset(st, 0, sizeof(*st));
    st->st_mode = (scenario == 1 ? S_IFLNK : S_IFREG) | (scenario == 2 ? 0775 : 0755);
    st->st_uid = scenario == 3 ? 501 : 0;
    st->st_nlink = scenario == 4 ? 2 : 1;
    st->st_size = scenario == 9 ? 0 : 2048;
    return 0;
}
static char *fake_realpath(const char *p, char *out) {
    if (scenario == 10) return NULL;
    const char *effective = scenario == 6 && strcmp(p, patchPath) == 0 ? "/outside/roothidepatch.dylib" : p;
    strcpy(out, effective);return out;
}
static void *fake_dlopen(const char *p, int flags) {
    if (strcmp(p, patchPath) || (flags & RTLD_NOW) != RTLD_NOW) return NULL;
    opened++;
    return scenario == 8 ? NULL : (void*)0x123;
}
static bool fake_macho(const char *p) {return scenario != 13 && strcmp(p,patchPath)==0;}
#define rh3_trust_looks_like_macho fake_macho
#define JBROOT_PATH(path) (!strcmp((path), "/usr/lib/roothidepatch.dylib") ? patchPath : !strcmp((path), "/var/jb") ? compatPath : NULL)
#define lstat fake_lstat
#define realpath fake_realpath
#define dlopen fake_dlopen
''' + loader + r'''
int main(void) {
    scenario = 0;opened = 0;
    if (rh3_load_rooted_patch(root) != 0 || opened != 1) return 1;
    for (scenario = 1; scenario <= 6; scenario++) {
        opened = 0;int result=rh3_load_rooted_patch(root);
        if ((scenario==5 && result!=0) || (scenario!=5 && result==0)) return 50+scenario;
        if (opened) return 10 + scenario;
    }
    for (scenario = 9; scenario <= 15; scenario++) {
        opened = 0;if (rh3_load_rooted_patch(root)==0) return 60+scenario;
        if (opened) return 20 + scenario;
    }
    scenario = 8;opened = 0;if (rh3_load_rooted_patch(root)!=EIO) return 33;
    if (opened != 1) return 31;
    scenario = 0;opened = 0;rh3_load_rooted_patch("/var/not-the-root");
    if (opened) return 32;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            test_source = Path(directory) / 'patch.c'
            # Windows installer detection treats patch.exe as requiring admin.
            binary = Path(directory) / 'runtime_probe.exe'
            test_source.write_text(test, encoding='utf-8')
            build = subprocess.run([cc, '-std=c11', '-I', str(PORT.parent / 'common'),
                                    str(test_source), '-o', str(binary)],
                                   text=True, capture_output=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == '__main__':
    unittest.main()
