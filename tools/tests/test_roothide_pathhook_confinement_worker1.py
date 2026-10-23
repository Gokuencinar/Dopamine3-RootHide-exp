"""Host-only regression for the production, root-confined pathhook loader.

This does not exercise iOS dyld, the actual signed dylib, or any device hook.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PORT = ROOT / "BaseBin/systemhook/src/roothider_port.c"
POLICY = ROOT / "BaseBin/systemhook/src/common"


class RootHidePathHookConfinement(unittest.TestCase):
    def test_loader_has_no_global_xpc_or_outside_root_fallback(self):
        text = PORT.read_text(encoding="utf-8")
        loader = text.split("static void roothide_call_pathhook(", 1)[1].split(
            "static int rh3_load_rooted_init(", 1
        )[0]
        process = text.split("void roothide_prepare_process(", 1)[1].split(
            "int roothide_trust_injected_libraries(", 1
        )[0]
        self.assertIn("roothide_call_pathhook(root)", process)
        self.assertIn("root_contains_executable(root, executable)", process)
        for needed in ("systemhook_is_roothide_root_path(root)",
                       "rh3_trust_is_active_root_child(path, root)",
                       "lstat(path, &st)", "S_ISREG(st.st_mode)",
                       "st.st_uid != 0", "st.st_nlink != 1", "st.st_mode & 0022",
                       "realpath(root, resolvedRoot)", "realpath(path, resolvedHook)",
                       "rh3_trust_is_active_root_child(resolvedHook, resolvedRoot)",
                       "dlopen(path, RTLD_NOW | RTLD_LOCAL)"):
            self.assertIn(needed, loader)
        for forbidden in ("jbclient_roothide_jailbroken", "xpc_", "jbdSpawnPatchChild",
                          "MSHookFunction", "chown(", "chmod(", "setenv("):
            self.assertNotIn(forbidden, loader)

    def test_real_loader_refuses_symlinks_unsafe_metadata_and_escape(self):
        compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not compiler:
            self.skipTest("C compiler not available on host")

        source = PORT.read_text(encoding="utf-8")
        loader = "static void roothide_call_pathhook(" + source.split(
            "static void roothide_call_pathhook(", 1
        )[1].split("static int rh3_load_rooted_init(", 1)[0]
        harness = r'''
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <dlfcn.h>
#include "roothide_trust_policy.h"
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_IFIFO
#define S_IFIFO 0010000
#endif

static const char root[] = "/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF";
static char hookPath[] = "/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/basebin/roothidehooks.dylib";
static int scenario, openAttempts, installs;
static bool systemhook_is_roothide_root_path(const char *path) {
    return path && strcmp(path, root) == 0;
}
static int fake_lstat(const char *path, struct stat *st) {
    if (strcmp(path, hookPath) || scenario == 11) return -1;
    memset(st, 0, sizeof(*st));
    st->st_mode = (scenario == 1 ? S_IFLNK : scenario == 5 ? S_IFIFO : S_IFREG)
                  | (scenario == 2 ? 0775 : 0755);
    st->st_uid = scenario == 3 ? 501 : 0;
    st->st_nlink = scenario == 4 ? 2 : 1;
    st->st_size = scenario == 10 ? 0 : 1024;
    return 0;
}
static char *fake_realpath(const char *path, char *buffer) {
    if (scenario == 6 && strcmp(path, root) == 0) return NULL;
    const char *resolved = scenario == 7 && strcmp(path, hookPath) == 0
                           ? "/outside/untrusted.dylib" : path;
    if (strlen(resolved) >= PATH_MAX) return NULL;
    strcpy(buffer, resolved);
    return buffer;
}
static void pathhook_installed(void) { installs++; }
static void *fake_dlopen(const char *path, int flags) {
    /* RTLD_LOCAL is zero on some hosts; compare rather than testing a bit. */
    if (strcmp(path, hookPath) || (flags & RTLD_NOW) != RTLD_NOW ||
        (flags & RTLD_LOCAL) != RTLD_LOCAL)
        return NULL;
    openAttempts++;
    return scenario == 8 ? NULL : (void*)0x55;
}
static void *fake_dlsym(void *library, const char *symbol) {
    if (library != (void*)0x55 || strcmp(symbol, "pathhook") || scenario == 9)
        return NULL;
    return (void*)&pathhook_installed;
}
#define JBROOT_PATH(path) (strcmp((path), "/basebin/roothidehooks.dylib") ? NULL : hookPath)
#define lstat fake_lstat
#define realpath fake_realpath
#define dlopen fake_dlopen
#define dlsym fake_dlsym
''' + loader + r'''
int main(void) {
    scenario = 0; openAttempts = installs = 0;
    roothide_call_pathhook(root);
    if (openAttempts != 1 || installs != 1) return 1;
    for (scenario = 1; scenario <= 7; scenario++) {
        openAttempts = installs = 0;
        roothide_call_pathhook(root);
        if (openAttempts || installs) return 10 + scenario;
    }
    for (scenario = 10; scenario <= 11; scenario++) {
        openAttempts = installs = 0;
        roothide_call_pathhook(root);
        if (openAttempts || installs) return 20 + scenario;
    }
    scenario = 8; openAttempts = installs = 0;
    roothide_call_pathhook(root);
    if (openAttempts != 1 || installs) return 40;
    scenario = 9; openAttempts = installs = 0;
    roothide_call_pathhook(root);
    if (openAttempts != 1 || installs) return 41;
    scenario = 0; openAttempts = installs = 0;
    roothide_call_pathhook("/var/not-the-authenticated-root");
    if (openAttempts || installs) return 42;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            test_source = Path(directory) / "pathhook.c"
            binary = Path(directory) / "pathhook.exe"
            test_source.write_text(harness, encoding="utf-8")
            built = subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-I", str(POLICY),
                 str(test_source), "-o", str(binary)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            checked = subprocess.run([str(binary)], capture_output=True,
                                     text=True, timeout=10)
            self.assertEqual(checked.returncode, 0, checked.stderr)


if __name__ == "__main__":
    unittest.main()
