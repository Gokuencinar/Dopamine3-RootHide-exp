"""Regression guards for the RootHide/stock systemhook injection boundary.

The shared C hook runs in launchd as well as systemhook, so the path decision
must not depend on asking launchd's XPC server to identify itself. These tests
check the integration contract; an actual iOS build/device test is separate.
"""

from pathlib import Path
import re
import json
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class RootHideInjectionTests(unittest.TestCase):
    def test_shared_path_selector_preserves_stock_and_private_roothide(self) -> None:
        header = source("BaseBin/systemhook/src/common/common.h")
        common = source("BaseBin/systemhook/src/common/common.c")

        self.assertIn('#define STOCK_HOOK_DYLIB_PATH "/usr/lib/systemhook.dylib"', header)
        self.assertIn("#define HOOK_DYLIB_PATH systemhook_dylib_path()", header)
        self.assertIn("const char *systemhook_dylib_path(void)", common)
        self.assertIn("systemhook_is_roothide_root_path(get_jbroot())", common)
        self.assertIn('JBROOT_PATH("/basebin/systemhook.dylib")', common)
        self.assertIn("return STOCK_HOOK_DYLIB_PATH;", common)
        self.assertIn("_Thread_local char resolvedPath[PATH_MAX]", common)

        # Both canonical and /private-prefixed container paths are accepted,
        # but arbitrary paths and substrings do not trigger RootHide injection.
        self.assertIn('"/var/containers/Bundle/Application/.jbroot-"', common)
        self.assertIn('"/private/var/containers/Bundle/Application/.jbroot-"', common)
        self.assertIn("length == sizeof(prefix) - 1 + 16", common)
        self.assertIn("check == (uint8_t)value", common)

    def test_spawn_and_exec_use_the_selected_path_consistently(self) -> None:
        common = source("BaseBin/systemhook/src/common/common.c")
        hook = common.split("static int spawn_exec_hook_common(", 1)[1].split(
            "int posix_spawn_hook_shared(", 1
        )[0]
        self.assertIn("const char *hookDylibPath = HOOK_DYLIB_PATH;", hook)
        self.assertIn("access(hookDylibPath, F_OK)", hook)
        self.assertIn("normalized_systemhook_inserts(existingLibraryInserts,", hook)
        self.assertIn("shouldInsertJBEnv ? hookDylibPath : NULL", hook)
        self.assertIn("strcmp(existingLibraryInserts, normalizedInserts)", hook)
        self.assertIn('envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", normalizedInserts)', hook)
        self.assertIn('envbuf_unsetenv(&envc, "DYLD_INSERT_LIBRARIES")', hook)
        self.assertIn('envbuf_unsetenv(&envc, "_SafeMode")', hook)
        self.assertIn('envbuf_unsetenv(&envc, "_MSSafeMode")', hook)
        self.assertNotIn("access(HOOK_DYLIB_PATH", hook)
        self.assertNotIn('"/usr/lib/systemhook.dylib"', hook)

        # Both launchd and already-injected processes call the same helper.
        self.assertIn("spawn_exec_hook_common(false,", common)
        self.assertIn("spawn_exec_hook_common(true,", common)

    def test_reboot_does_not_mount_fakelib_in_roothide(self) -> None:
        launchd = source("BaseBin/launchdhook/src/spawn_hook.c")
        mounting = launchd.split("void ensure_fakelib_mounted(void)", 1)[1].split(
            "int __posix_spawn_orig_wrapper(", 1
        )[0]
        self.assertIn("roothide_is_active() || roothide_launchdhook_origin_verified()", mounting)
        self.assertIn("systemhook_is_roothide_root_path(root)", launchd)
        self.assertIn("dladdr((const void *)&roothide_launchdhook_origin_verified, &image)", launchd)
        self.assertIn('"/basebin/launchdhook.dylib"', launchd)
        self.assertIn("rh3_pid1_var_alias_n(image.dli_fname, &imageLength)", launchd)
        self.assertIn("!memcmp(imageName, root, rootLength)", launchd)
        self.assertLess(mounting.index("roothide_is_active()"), mounting.index('statfs("/usr/lib"'))
        self.assertIn('"fakelib", "mount"', mounting)
        self.assertIn("ensure_fakelib_mounted();", launchd)

    def test_compiled_c_normalization_keeps_other_dylibs_and_rejects_spoofs(self) -> None:
        """Compile the actual C helpers, rather than a Python copy of their logic."""
        compiler = shutil.which("clang") or shutil.which("gcc") or shutil.which("cc")
        if not compiler:
            self.skipTest("C compiler unavailable; iOS CI should compile these helpers")

        common = source("BaseBin/systemhook/src/common/common.c")
        snippet = common.split("static bool is_roothide_root_path_n(", 1)[1].split(
            "const char *systemhook_dylib_path(void)", 1
        )[0]
        snippet = "static bool is_roothide_root_path_n(" + snippet

        def branded_root(prefix: str, seed: int) -> str:
            seed &= ~0xFF
            check = 0
            for shift in range(8, 64, 8):
                check ^= (seed >> shift) & 0xFF
            return f"{prefix}.jbroot-{seed | check:016X}"

        base = "/var/containers/Bundle/Application/"
        hidden_root = branded_root(base, 0x8B2173C4D5E6F700)
        previous_root = branded_root("/private" + base, 0xA16C5B4D3E2F7800)
        hidden = hidden_root + "/basebin/systemhook.dylib"
        stale_hidden = previous_root + "/basebin/systemhook.dylib"
        stock = "/usr/lib/systemhook.dylib"
        third = "/Library/MobileSubstrate/DynamicLibraries/Keep.dylib"
        other = "/usr/lib/ThirdParty.dylib"
        fake = "/tmp/.jbroot-1234567890ABCDEF/basebin/systemhook.dylib"
        near_match = hidden + ".foreign"

        cases = [
            (stock + ":" + third, hidden, hidden + ":" + third),
            (stale_hidden + ":" + third, stock, stock + ":" + third),
            (stock + ":" + hidden + ":" + stale_hidden + ":" + third + ":" + other,
             None, third + ":" + other),
            (stock + ":" + hidden + ":" + hidden + ":" + other,
             hidden, hidden + ":" + other),
            (fake + ":" + near_match + ":" + stock,
             None, fake + ":" + near_match),
            (None, stock, stock),
            (None, None, ""),
            (":".join([other] * 1000 + [stock]), hidden,
             hidden + ":" + ":".join([other] * 1000)),
        ]

        assertions = []
        for old, selected, expected in cases:
            old_arg = json.dumps(old) if old is not None else "NULL"
            selected_arg = json.dumps(selected) if selected is not None else "NULL"
            assertions.append(
                "check_normalized(" + old_arg + ", " + selected_arg + ", "
                + json.dumps(expected) + ");"
            )
        assertions.extend([
            f"check_root({json.dumps(hidden_root)}, true);",
            f"check_root({json.dumps(previous_root)}, true);",
            f"check_root({json.dumps(hidden_root[:-1] + '0')}, false);",
            'check_root("/private/preboot/.jbroot-8B2173C4D5E6F700", false);',
        ])

        harness = "\n".join([
            "#include <stdbool.h>",
            "#include <stdint.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
            "#include <stdio.h>",
            '#define STOCK_HOOK_DYLIB_PATH "/usr/lib/systemhook.dylib"',
            snippet,
            "static void check_root(const char *path, bool expected) {",
            "  if (systemhook_is_roothide_root_path(path) != expected) exit(31);",
            "}",
            "static void check_normalized(const char *old, const char *selected, const char *expected) {",
            "  char *actual = normalized_systemhook_inserts(old, selected);",
            "  if (!actual || strcmp(actual, expected)) { fprintf(stderr, \"mismatch\\n\"); exit(32); }",
            "  free(actual);",
            "}",
            "int main(void) {",
            *assertions,
            "  return 0;",
            "}",
        ])

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "roothide_injection_test.c"
            program = Path(folder) / "roothide_injection_test"
            path.write_text(harness, encoding="utf-8")
            built = subprocess.run(
                [compiler, "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror", str(path), "-o", str(program)],
                text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            tested = subprocess.run([str(program)], text=True, capture_output=True, timeout=10)
            self.assertEqual(tested.returncode, 0, tested.stderr)

    def test_existing_blacklist_and_gate_remain_intact(self) -> None:
        launchd = source("BaseBin/launchdhook/src/spawn_hook.c")
        self.assertIn("isBlacklistedPath(path) || roothide_blacklisted_uikit_proxy(path, argv)", launchd)
        self.assertIn('strncmp(envp[i], "DYLD_INSERT_LIBRARIES=", 22)', launchd)
        self.assertIn("roothide_spawn_uninjected(trackedPid, path, desc, argv, envp)", launchd)
        self.assertIn("posix_spawn_hook_shared(pid, path, desc, argv, envp", launchd)
        bootstrap = source("Application/Dopamine/Jailbreak/DOBootstrapper.m")
        self.assertIn("#define ROOTHIDE3_BOOTSTRAP_READY 0", bootstrap)


if __name__ == "__main__":
    unittest.main()
