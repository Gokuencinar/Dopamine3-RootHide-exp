"""Build graph, cache scope, and internal-package publication safeguards.

These checks inspect source on Windows too. Real macOS compile outputs and
cache hit rates must still be verified in a GitHub Actions run.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOP = (ROOT / "Makefile").read_text(encoding="utf-8")
PACKAGES = (ROOT / "Packages/Makefile").read_text(encoding="utf-8")
CI = (ROOT / ".github/workflows/main.yml").read_text(encoding="utf-8")


class ParallelBuildAndCacheTests(unittest.TestCase):
    def test_producers_are_dependencies_not_four_serial_recipes(self):
        self.assertRegex(TOP, r"(?m)^all: application standalone$")
        self.assertRegex(TOP, r"(?m)^packages: basebin$")
        self.assertRegex(TOP, r"(?m)^application: packages$")
        self.assertRegex(TOP, r"(?m)^standalone: packages$")
        self.assertRegex(TOP, r"(?m)^basebin:\s*\n\t@\$\(MAKE\) -C BaseBin$")
        self.assertNotRegex(TOP, r"(?m)^all:\s*\n\t@\$\(MAKE\)")
        self.assertIn("gmake -j$(sysctl -n hw.logicalcpu)", CI)

    def test_dependency_debs_build_in_parallel_after_basebin(self):
        self.assertRegex(PACKAGES,
                         r"(?m)^all: libkrw-provider libroot basebin-link$")
        for subproject in ("libkrw-provider", "libroot", "basebin-link"):
            self.assertRegex(PACKAGES, rf"(?m)^{subproject}:\s*\n"
                                       rf"\t@\$\(MAKE\) -C {subproject} package$")

    def test_independent_workflow_runs_are_not_cancelled(self):
        self.assertNotRegex(CI, r"(?m)^concurrency:\s*$")
        self.assertIn("github.run_number", CI)
        self.assertIn("github.run_attempt", CI)

    def test_object_cache_works_for_trusted_experimental_branches(self):
        self.assertIn("id: rh3_object_cache", CI)
        self.assertIn("id: ccache_setup", CI)
        self.assertIn("cache_day=$(date -u +%Y%m%d)", CI)
        self.assertIn("rh3-objects-macos15-xcode-", CI)
        self.assertIn("actions/cache/restore@v4", CI)
        self.assertIn("actions/cache/save@v4", CI)
        self.assertRegex(CI, r"if: always\(\) && steps.ccache_setup.outcome == 'success'"
                             r" && steps.rh3_object_cache.outcome == 'success'")
        self.assertIn("steps.rh3_object_cache.outputs.cache-hit != 'true'", CI)
        self.assertGreaterEqual(
            CI.count("startsWith(github.ref, 'refs/heads/roothide-')"), 4)
        self.assertIn("github.event_name != 'pull_request'", CI)
        self.assertIn("CCACHE_MAXSIZE=512M", CI)
        # Never store signed binaries, jailbreak root, or packaged IPAs.
        cache = CI.split("- name: Restore RootHide object cache", 1)[1].split(
            "- name: Configure incremental", 1)[0]
        self.assertIn("~/.cache/ccache-roothide3", cache)
        self.assertNotIn("Application/Dopamine.ipa", cache)
        self.assertNotIn("BaseBin/basebin.tar", cache)

    def test_three_real_packages_verified_before_upload(self):
        verification = CI.index("- name: Verify compiled internal dependency DEBs")
        publication = CI.index("- name: Upload verified internal dependency DEBs")
        strict_gate = CI.index("- name: Check RootHide port prerequisites before upload")
        self.assertLess(verification, publication)
        self.assertLess(publication, strict_gate)
        for folder, deb, identity in (
            ("libkrw-provider", "libkrw-dopamine", "libkrw0-dopamine"),
            ("libroot", "libroot", "libroot-dopamine"),
            ("basebin-link", "basebin-link", "dopamine-basebin-link"),
        ):
            with self.subTest(deb=deb):
                self.assertIn(f"Packages/{folder}/{deb}.deb:{identity}", CI)
                self.assertIn(f"Packages/{folder}/{deb}.deb", CI)
        for validation in ("dpkg-deb --field", "dpkg-deb --info", "dpkg-deb --contents",
                           "shasum -a 256", "test ! -L", "if-no-files-found: error",
                           "RootHide3-INTERNAL-DEBS-NOT-FOR-INSTALL"):
            with self.subTest(validation=validation):
                self.assertIn(validation, CI)
        self.assertIn("ROOTHIDE_HARDWARE_TEST", CI)
        self.assertNotIn("RootHide3-JAILBREAK-FIX.deb", CI)


if __name__ == "__main__":
    unittest.main()
