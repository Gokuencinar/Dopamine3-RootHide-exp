"""Keep recursive trust confined to current RootHide files, not Apple children."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "BaseBin/systemhook/src/common/roothide_trust_policy.h"
MAIN = ROOT / "BaseBin/systemhook/src/main.c"


class RecursiveTrustScope(unittest.TestCase):
    def test_active_root_apt_dependency_trust_runs_even_with_private_dyld_patch(self):
        src = MAIN.read_text(encoding="utf-8")
        method = src.split("static int rh3_trust_before_spawn(", 1)[1].split(
            "int __posix_spawn_hook(", 1)[0]
        # The private-dyld mode must not suppress the APT method's recursive
        # pretrust: the ordinary single-file trust misses libgnutls.@rpath.
        recursion = method.index("jbclient_trust_executable_recurse(path, preferredArchs)")
        self.assertIn("getpid() == 1", method[:recursion],
                      "Never introduce synchronous trust-service IPC in PID1")
        self.assertNotIn("jbclient_dyld_patch_enabled()", method[:recursion],
                         "Mode selection must not bypass active-root dependency closure")
        # Keep original dyld-mode policy for unrelated Apple/system jobs.
        self.assertIn("if (jbclient_dyld_patch_enabled()) return 0;", method[recursion:])
        self.assertIn("rh3_spawn_canonical_root_child(path, root)", method[:recursion])

    def test_actual_spawn_preflight_scopes_executable_but_not_inserted_libraries(self):
        src = MAIN.read_text(encoding="utf-8")
        method = src.split("static int rh3_trust_before_spawn(", 1)[1].split(
            "int __posix_spawn_hook(", 1)[0]
        self.assertLess(method.index("rh3_trust_is_active_root_child(path, root)"),
                        method.index("jbclient_trust_executable_recurse(path, preferredArchs)"))
        self.assertLess(method.index("rh3_spawn_canonical_root_child(path, root)"),
                        method.index("jbclient_trust_executable_recurse(path, preferredArchs)"))
        self.assertIn("if (activeRootChild)", method)
        self.assertIn("if (rh3_trust_looks_like_macho(path)) return EACCES;", method)
        # Even a stock UIKit executable may request an authenticated hidden
        # library via DYLD_INSERT_LIBRARIES; its trust is a separate decision.
        self.assertIn("return roothide_trust_injected_libraries(envp);", method)
        self.assertNotIn("jbdSpawnPatchChild", method)

    def test_scripts_and_non_macho_root_files_never_enter_recursive_trust_xpc(self):
        source = MAIN.read_text(encoding="utf-8")
        method = source.split("static int rh3_trust_before_spawn(", 1)[1].split(
            "int __posix_spawn_hook(", 1)[0]
        recursive_call = method.index("jbclient_trust_executable_recurse(path, preferredArchs)")
        self.assertIn("else if (rh3_trust_looks_like_macho(path)) {",
                      method[:recursive_call])
        self.assertLess(method.index("else if (rh3_trust_looks_like_macho(path)) {"),
                        recursive_call)

    def test_native_extracted_preflight_rejects_symlink_escape_and_old_root(self):
        cc = shutil.which("clang") or shutil.which("gcc") or shutil.which("cc")
        if not cc:
            self.skipTest("Host C compiler unavailable")
        main = MAIN.read_text(encoding="utf-8")
        fn = main.split("static bool rh3_spawn_canonical_root_child(", 1)[1].split(
            "static int rh3_trust_before_spawn(", 1)[0]
        code = r'''
#include "roothide_trust_policy.h"
#include <stdio.h>
#include <string.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
// Mock only the filesystem resolver, exercising the exact production policy.
static char *realpath(const char *path, char *dest) {
    if (strstr(path, "/missing")) return NULL;
    if (strstr(path, "/escaped")) path = "/System/Library/escaped";
    strcpy(dest, path);
    return dest;
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); return 1; } } while (0)
static bool rh3_spawn_canonical_root_child(
'''
        code += fn
        code += r'''
int main(void) {
    const char *root = "/var/containers/Bundle/Application/.jbroot-0000000000000001";
    const char *own = "/var/containers/Bundle/Application/.jbroot-0000000000000001/usr/bin/login";
    const char *outside = "/usr/libexec/xpcproxy";
    const char *escape = "/var/containers/Bundle/Application/.jbroot-0000000000000001/usr/bin/escaped";
    const char *oldRoot = "/var/containers/Bundle/Application/.jbroot-0000000000000002/usr/bin/login";
    const char *missing = "/var/containers/Bundle/Application/.jbroot-0000000000000001/usr/bin/missing";
    CHECK(rh3_spawn_canonical_root_child(own, root));
    CHECK(!rh3_spawn_canonical_root_child(root, root));
    CHECK(!rh3_spawn_canonical_root_child(outside, root));
    CHECK(!rh3_spawn_canonical_root_child(escape, root));
    CHECK(!rh3_spawn_canonical_root_child(oldRoot, root));
    CHECK(!rh3_spawn_canonical_root_child(missing, root));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            temp = Path(d)
            src = temp / "trust.c"
            exe = temp / "trust.exe"
            src.write_text(code, encoding="utf-8")
            build = subprocess.run([cc, "-std=c11", "-I", str(HEADER.parent),
                                    str(src), "-o", str(exe)], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(exe)],
                                 capture_output=True, text=True, timeout=8)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
