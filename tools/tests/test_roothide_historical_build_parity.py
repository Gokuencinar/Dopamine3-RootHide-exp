"""Contracts for the RootHide 2 -> Dopamine 3 build migration.

These are source assertions: they do not validate the app's actual jailbreak,
code signatures, or on-device filesystem changes.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class HistoricalRootHidePortTests(unittest.TestCase):
    def test_donor_basebin_components_coexist_with_new_dopamine_components(self):
        makefile = source("BaseBin/Makefile")
        for name in (
            "libjailbreak", "systemhook", "launchdhook", "dyldhook",
            "roothidehooks", "bootstrapper", "jailbreakd", "hookd",
            "rootlesshooks", "dopamine",
        ):
            with self.subTest(name=name):
                self.assertRegex(makefile, rf"(?m)^{name}:|\b{name}\b")
        self.assertIn("basebin.tc: subprojects", makefile)
        self.assertIn("basebin.tar: basebin.tc dyldhook", makefile)

    def test_experimental_cli_does_not_execute_stock_install_or_activation(self):
        makefile = source("BaseBin/dopamine/Makefile")
        cli = source("BaseBin/dopamine/src/main.m")
        workflow = source(".github/workflows/main.yml")
        self.assertIn("ROOTHIDE_EXPERIMENTAL_BUILD ?= $(if $(wildcard ../libjailbreak/src/roothider.h),1,0)", makefile)
        self.assertIn("-DROOTHIDE_EXPERIMENTAL_BUILD=$(ROOTHIDE_EXPERIMENTAL_BUILD)", makefile)
        self.assertIn("ROOTHIDE_EXPERIMENTAL_BUILD: ${{ steps.roothide_port.outputs.is_port == 'true' && '1' || '0' }}", workflow)
        guard = cli.index("#if ROOTHIDE_EXPERIMENTAL_BUILD", cli.index("int main("))
        invoke = cli.index('gJb = [[DOJailbreaker alloc] init]', guard)
        self.assertLess(guard, invoke)
        guarded = cli[guard:invoke]
        self.assertIn('!strcmp(argv[1], "install")', guarded)
        self.assertIn('!strcmp(argv[1], "activate")', guarded)
        self.assertRegex(guarded, r"return 78\s*;")
        self.assertIn("#endif", guarded)
        # The stock route remains present so a conventional Dopamine3 build
        # (flag 0) does not lose its existing Corellium CLI functionality.
        self.assertIn("install_dopamine();", cli[invoke:])
        self.assertIn("activate_dopamine();", cli[invoke:])

    def test_historical_placeholder_bootstrapper_cannot_claim_success(self):
        bootstrapper = source("BaseBin/bootstrapper/src/main.m")
        self.assertIn("not implemented", bootstrapper)
        self.assertIn("return 78;", bootstrapper)
        self.assertNotRegex(bootstrapper, r"return\s+0\s*;")

    def test_runtime_root_hide_still_requires_explicit_activation(self):
        bootstrap = source("Application/Dopamine/Jailbreak/DOBootstrapper.m")
        self.assertIn("#define ROOTHIDE3_BOOTSTRAP_READY 0", bootstrap)
        self.assertIn("rootHidePortEnabled", bootstrap)

    def test_first_activation_defers_global_injection_like_donor(self):
        launchd = source("BaseBin/launchdhook/src/main.m")
        spawn = source("BaseBin/launchdhook/src/spawn_hook.c")
        self.assertIn("if (roothide_is_active()) launchdhookFirstLoad = firstLoad;", launchd)
        self.assertLess(launchd.index("launchdhookFirstLoad = firstLoad;"),
                        launchd.index("initSpawnHooks();"))
        root_first = spawn.index("if (roothide_is_active() && launchdhookFirstLoad)")
        default_hook = spawn.index("return posix_spawn_hook_shared(", root_first)
        first = spawn[root_first:default_hook]
        self.assertIn("return EPERM;", first)
        self.assertIn("return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);", first)
        self.assertLess(root_first, spawn.index("isBlacklistedPath(path)", root_first))
        # The additional guard is only ever reached for an active hidden
        # root, not for stock Dopamine 3.
        self.assertIn("roothide_is_active() && launchdhookFirstLoad", first)


if __name__ == "__main__":
    unittest.main()
