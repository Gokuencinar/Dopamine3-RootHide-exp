"""Verify RootHide protection cannot silently depend on NIGHTLY=1.

On macOS/Linux, GNU Make dry-runs the actual recipes without Xcode. On Windows
without Make, structural checks still protect the branch ordering in review.
"""

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Application" / "Makefile"
BUNDLE_ID = "com.gokuencinar.roothide3.fulltest"


class RootHideBuildMatrixTests(unittest.TestCase):
    def test_explicit_experimental_switch_is_outside_nightly_branch(self):
        makefile = MAKEFILE.read_text(encoding="utf-8")
        nightly_metadata = makefile.index("DOPAMINE_NIGHTLY_DEFINITIONS :=")
        full_selector = makefile.index("ifeq ($(ROOTHIDE_EXPERIMENTAL_BUILD), 1)")
        stock_nightly = makefile.index("else ifeq ($(NIGHTLY), 1)", full_selector)
        self.assertLess(nightly_metadata, full_selector)
        self.assertLess(full_selector, stock_nightly)
        experimental = makefile[full_selector:stock_nightly]
        self.assertIn("PRODUCT_BUNDLE_IDENTIFIER=" + BUNDLE_ID, experimental)
        self.assertIn("RH3_FULL_APP_EXPERIMENTAL=1", experimental)
        self.assertIn("ROOTHIDE3_BOOTSTRAP_READY=0", experimental)
        self.assertIn("$(DOPAMINE_NIGHTLY_DEFINITIONS)", experimental)

    def test_effective_xcodebuild_args_for_all_four_build_modes(self):
        make = shutil.which("gmake") or shutil.which("make")
        if not make:
            self.skipTest("GNU Make unavailable on this Windows host; the CI runner executes this test")
        for experimental in ("0", "1"):
            for nightly in ("0", "1"):
                with self.subTest(experimental=experimental, nightly=nightly):
                    result = subprocess.run(
                        [make, "--no-print-directory", "-n", "-C", "Application",
                         "Dopamine.ipa",
                         f"ROOTHIDE_EXPERIMENTAL_BUILD={experimental}",
                         f"NIGHTLY={nightly}", "COMMIT_HASH=matrix-test-sha"],
                        cwd=ROOT, encoding="utf-8", errors="replace",
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    xcode_lines = [
                        line for line in result.stdout.splitlines()
                        if line.lstrip().startswith("xcodebuild ")
                    ]
                    self.assertEqual(len(xcode_lines), 1, result.stdout)
                    command = xcode_lines[0]
                    if experimental == "1":
                        self.assertIn("PRODUCT_BUNDLE_IDENTIFIER=" + BUNDLE_ID, command)
                        self.assertIn("RH3_FULL_APP_EXPERIMENTAL=1", command)
                        self.assertIn("ROOTHIDE3_BOOTSTRAP_READY=0", command)
                        self.assertIn("INFOPLIST_KEY_CFBundleDisplayName=", command)
                    else:
                        self.assertNotIn(BUNDLE_ID, command)
                        self.assertNotIn("RH3_FULL_APP_EXPERIMENTAL=1", command)
                    self.assertEqual("NIGHTLY=1" in command, nightly == "1")
                    self.assertEqual("matrix-test-sha" in command, nightly == "1")


if __name__ == "__main__":
    unittest.main()
