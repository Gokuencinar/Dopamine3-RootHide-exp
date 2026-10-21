"""Guard the dormant, NewTerm-only PID 1 patch-child compatibility experiment.

These are source-level invariants, not evidence of a safe on-device launchd
patch. In particular the feature must remain disabled for ordinary builds.
"""

from pathlib import Path
import re
import unittest


SOURCE = (Path(__file__).resolve().parents[2] /
          "BaseBin/launchdhook/src/spawn_hook.c").read_text(encoding="utf-8")
SELECTOR = SOURCE.split("static bool rh3_newterm_uikit_proxy(", 1)[1].split(
    "static int rh3_newterm_launchd_posthook(", 1)[0]
POSTHOOK = SOURCE.split("static int rh3_newterm_launchd_posthook(", 1)[1].split(
    "int __posix_spawn_hook(", 1)[0]
HOOK = SOURCE.split("int __posix_spawn_hook(", 1)[1].split(
    "void initSpawnHooks(", 1)[0]


class NewTermLaunchdParityTests(unittest.TestCase):
    def test_disabled_in_production_without_runtime_override(self):
        self.assertRegex(SOURCE, re.compile(
            r"#ifndef RH3_EXPERIMENTAL_NEWTERM_LAUNCHD_PATCH_CHILD\s*"
            r"#define RH3_EXPERIMENTAL_NEWTERM_LAUNCHD_PATCH_CHILD 0\b"
        ))
        self.assertNotIn('getenv("RH3_EXPERIMENTAL_NEWTERM_LAUNCHD_PATCH_CHILD")', SOURCE)
        self.assertIn("if (RH3_EXPERIMENTAL_NEWTERM_LAUNCHD_PATCH_CHILD &&", HOOK)

    def test_only_exact_newterm_uikit_xpcproxy_selected(self):
        self.assertIn('"/usr/libexec/xpcproxy"', SELECTOR)
        self.assertIn('"UIKitApplication:ws.hbang.Terminal["', SELECTOR)
        self.assertIn("!strncmp(argv[1], label, sizeof(label) - 1)", SELECTOR)
        self.assertNotIn("strstr(", SELECTOR)
        self.assertNotIn("NewTermLoginHelper", SELECTOR)

    def test_bypass_boot_firstload_and_blacklisted_before_patch(self):
        self.assertLess(HOOK.index("if (gInEarlyBoot)"),
                        HOOK.index("if (RH3_EXPERIMENTAL_NEWTERM_LAUNCHD_PATCH_CHILD &&"))
        self.assertLess(HOOK.index("if (roothide_is_active() && launchdhookFirstLoad)"),
                        HOOK.index("if (RH3_EXPERIMENTAL_NEWTERM_LAUNCHD_PATCH_CHILD &&"))
        self.assertLess(HOOK.index("roothide_spawn_uninjected("),
                        HOOK.index("if (RH3_EXPERIMENTAL_NEWTERM_LAUNCHD_PATCH_CHILD &&"))
        for guard in ("!gInEarlyBoot", "!launchdhookFirstLoad",
                      "roothide_launchdhook_origin_verified()",
                      "roothide_is_active()", "jailbreakd_has_checked_in()",
                      "rh3_newterm_uikit_proxy(path, argv)"):
            with self.subTest(guard=guard):
                self.assertIn(guard, HOOK)

    def test_pid1_never_queries_own_jbclient_for_patch(self):
        self.assertIn("jbdSpawnPatchChild(*childPid, resume)", POSTHOOK)
        self.assertNotIn("jbclient_roothide_patch_child", POSTHOOK.split("{", 1)[1])

    def test_suspension_ownership_and_failure_handling(self):
        for expected in (
            "if (!desc || !desc->attrp)",
            "POSIX_SPAWN_SETEXEC",
            "POSIX_SPAWN_PROC_TYPE_DRIVER",
            "const bool resume = (flags & POSIX_SPAWN_START_SUSPENDED) == 0;",
            "flags | POSIX_SPAWN_START_SUSPENDED",
            "pid_t *childPid = pid ? pid : &temporaryPid;",
            "posix_spawnattr_setflags(&attributes, flags);",
            "kill(*childPid, SIGKILL);",
            "if (pid) *pid = 0;",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, POSTHOOK)
        self.assertNotIn("waitpid(", POSTHOOK.split("{", 1)[1])
        self.assertNotIn("kill(*childPid, SIGCONT)", POSTHOOK)

    def test_stock_spawn_fallback_is_still_final(self):
        self.assertRegex(HOOK, re.compile(
            r"if \(RH3_EXPERIMENTAL_NEWTERM_LAUNCHD_PATCH_CHILD &&[\s\S]+?"
            r"return posix_spawn_hook_shared\(pid, path, desc, argv, envp, "
            r"__posix_spawn_orig_wrapper,"
        ))


if __name__ == "__main__":
    unittest.main()
