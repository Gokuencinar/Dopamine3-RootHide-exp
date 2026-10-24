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
        self.assertIn("RH3_APP_BUNDLE_IDENTIFIER=$(ROOTHIDE_EXPERIMENT_ID)", experimental)
        self.assertNotRegex(experimental, r"(?<![A-Z_])PRODUCT_BUNDLE_IDENTIFIER=")
        self.assertNotIn("INFOPLIST_KEY_CFBundleDisplayName=", experimental)
        project = (ROOT / "Application/Dopamine.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        self.assertEqual(project.count('PRODUCT_BUNDLE_IDENTIFIER = "$(RH3_APP_BUNDLE_IDENTIFIER)";'), 2)
        self.assertEqual(project.count('INFOPLIST_KEY_CFBundleDisplayName = "$(RH3_APP_DISPLAY_NAME)";'), 2)
        self.assertEqual(project.count('RH3_APP_BUNDLE_IDENTIFIER = com.opa334.Dopamine;'), 2)
        self.assertIn("ROOTHIDE_EXPERIMENT_ID := " + BUNDLE_ID, makefile)
        self.assertIn("RH3_FULL_APP_EXPERIMENTAL=1", experimental)
        self.assertIn("ROOTHIDE3_BOOTSTRAP_READY=$(ROOTHIDE_BOOTSTRAP_GATE)", experimental)
        self.assertIn("ROOTHIDE_BOOTSTRAP_GATE := 0", makefile)
        self.assertIn("ROOTHIDE_BOOTSTRAP_GATE := 1", makefile)
        self.assertIn("ROOTHIDE_TWEAKS_DEFAULT_ON := 0", makefile)
        self.assertIn("ROOTHIDE_TWEAKS_DEFAULT_ON := 1", makefile)
        self.assertIn("ROOTHIDE3_TWEAKS_DEFAULT_ON=$(ROOTHIDE_TWEAKS_DEFAULT_ON)", makefile)
        self.assertIn("$(DOPAMINE_NIGHTLY_DEFINITIONS)", experimental)

    def test_xcode_cache_launcher_requires_explicit_opt_in(self):
        makefile = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn('ifeq ($(RH3_CCACHE),1)', makefile)
        self.assertIn('RH3_XCODE_CCACHE_ARGS := C_COMPILER_LAUNCHER=', makefile)
        self.assertIn('CXX_COMPILER_LAUNCHER=', makefile)
        self.assertEqual(makefile.count('$(RH3_XCODE_CCACHE_ARGS)'), 3)
        make = shutil.which("gmake") or shutil.which("make")
        if not make or not shutil.which("ccache"):
            self.skipTest("Native GNU Make and ccache are exercised on macOS CI")
        for enabled in ("0", "1"):
            result = subprocess.run(
                [make, "--no-print-directory", "-n", "-C", "Application",
                 "Dopamine.ipa", "ROOTHIDE_EXPERIMENTAL_BUILD=1",
                 "ROOTHIDE_HARDWARE_TEST=YES", "ROOTHIDE_ALL_ENABLED=NO",
                 f"RH3_CCACHE={enabled}"],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            command = next(line for line in result.stdout.splitlines()
                           if line.lstrip().startswith("xcodebuild "))
            self.assertEqual("C_COMPILER_LAUNCHER=" in command, enabled == "1")
            self.assertEqual("CXX_COMPILER_LAUNCHER=" in command, enabled == "1")

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
                         "ROOTHIDE_HARDWARE_TEST=NO",
                         "ROOTHIDE_ALL_ENABLED=NO",
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
                        self.assertIn("RH3_APP_BUNDLE_IDENTIFIER=" + BUNDLE_ID, command)
                        self.assertIn("RH3_FULL_APP_EXPERIMENTAL=1", command)
                        self.assertIn("ROOTHIDE3_BOOTSTRAP_READY=0", command)
                        self.assertIn("ROOTHIDE3_TWEAKS_DEFAULT_ON=0", command)
                        self.assertIn("RH3_APP_DISPLAY_NAME=", command)
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
                     "ROOTHIDE_HARDWARE_TEST=YES", "ROOTHIDE_ALL_ENABLED=NO",
                     f"NIGHTLY={nightly}",
                     "COMMIT_HASH=hardware-test-sha"],
                    cwd=ROOT, encoding="utf-8", errors="replace",
                    capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                command = next(line for line in result.stdout.splitlines()
                               if line.lstrip().startswith("xcodebuild "))
                self.assertIn("RH3_APP_BUNDLE_IDENTIFIER=" + BETA_BUNDLE_ID, command)
                self.assertIn("ROOTHIDE3_BOOTSTRAP_READY=1", command)
                self.assertIn("ROOTHIDE3_TWEAKS_DEFAULT_ON=0", command)
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

    def test_explicit_all_enabled_requires_manual_hardware_beta(self):
        makefile = MAKEFILE.read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertIn("ROOTHIDE_ALL_ENABLED=YES requires ROOTHIDE_HARDWARE_TEST=YES", makefile)
        self.assertIn("inputs.hardware_beta == true && inputs.all_enabled == true", workflow)
        make = shutil.which("gmake") or shutil.which("make")
        if not make:
            return
        for hardware, enabled, accepted in (("NO", "YES", False),
                                            ("YES", "YES", True),
                                            ("YES", "NO", True)):
            with self.subTest(hardware=hardware, enabled=enabled):
                result = subprocess.run([make, "--no-print-directory", "-n", "-C", "Application",
                                         "Dopamine.ipa", "ROOTHIDE_EXPERIMENTAL_BUILD=1",
                                         f"ROOTHIDE_HARDWARE_TEST={hardware}",
                                         f"ROOTHIDE_ALL_ENABLED={enabled}"], cwd=ROOT,
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if accepted:
                    command = next(x for x in result.stdout.splitlines()
                                   if x.lstrip().startswith("xcodebuild "))
                    self.assertIn(f"ROOTHIDE3_TWEAKS_DEFAULT_ON={int(enabled == 'YES')}", command)


if __name__ == "__main__":
    unittest.main()
