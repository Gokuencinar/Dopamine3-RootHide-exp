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
BETA_BUNDLE_ID = "com.gokuencinar.roothide3.hardwarebeta"


class RootHideBuildMatrixTests(unittest.TestCase):
    def test_explicit_experimental_switch_is_outside_nightly_branch(self):
        makefile = MAKEFILE.read_text(encoding="utf-8")
        nightly_metadata = makefile.index("DOPAMINE_NIGHTLY_DEFINITIONS :=")
        full_selector = makefile.index("ifeq ($(ROOTHIDE_EXPERIMENTAL_BUILD), 1)")
        stock_nightly = makefile.index("else ifeq ($(NIGHTLY), 1)", full_selector)
        self.assertLess(nightly_metadata, full_selector)
        self.assertLess(full_selector, stock_nightly)
        experimental = makefile[full_selector:stock_nightly]
        self.assertIn("PRODUCT_BUNDLE_IDENTIFIER=$(ROOTHIDE_EXPERIMENT_ID)", experimental)
        self.assertIn("ROOTHIDE_EXPERIMENT_ID := " + BUNDLE_ID, makefile)
        self.assertIn("RH3_FULL_APP_EXPERIMENTAL=1", experimental)
        self.assertIn("ROOTHIDE3_BOOTSTRAP_READY=$(ROOTHIDE_BOOTSTRAP_GATE)", experimental)
        self.assertIn("ROOTHIDE_BOOTSTRAP_GATE := 0", makefile)
        self.assertIn("ROOTHIDE_BOOTSTRAP_GATE := 1", makefile)
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

    def test_manual_hardware_beta_build_has_distinct_gate_and_identity(self):
        make = shutil.which("gmake") or shutil.which("make")
        if not make:
            self.skipTest("GNU Make unavailable; macOS CI tests real recipes")
        for nightly in ("0", "1"):
            with self.subTest(nightly=nightly):
                result = subprocess.run(
                    [make, "--no-print-directory", "-n", "-C", "Application",
                     "Dopamine.ipa", "ROOTHIDE_EXPERIMENTAL_BUILD=1",
                     "ROOTHIDE_HARDWARE_TEST=YES", f"NIGHTLY={nightly}",
                     "COMMIT_HASH=hardware-test-sha"],
                    cwd=ROOT, encoding="utf-8", errors="replace",
                    capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                command = next(line for line in result.stdout.splitlines()
                               if line.lstrip().startswith("xcodebuild "))
                self.assertIn("PRODUCT_BUNDLE_IDENTIFIER=" + BETA_BUNDLE_ID, command)
                self.assertIn("ROOTHIDE3_BOOTSTRAP_READY=1", command)
                self.assertIn("RH3_FULL_APP_EXPERIMENTAL=1", command)
                self.assertNotIn(BUNDLE_ID, command)
                self.assertEqual("hardware-test-sha" in command, nightly == "1")
        result = subprocess.run(
            [make, "--no-print-directory", "-n", "-C", "Application",
             "Dopamine.ipa", "ROOTHIDE_EXPERIMENTAL_BUILD=0",
             "ROOTHIDE_HARDWARE_TEST=YES"],
            cwd=ROOT, encoding="utf-8", errors="replace",
            capture_output=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires ROOTHIDE_EXPERIMENTAL_BUILD=1", result.stderr)


if __name__ == "__main__":
    unittest.main()
