"""Cross-architecture support contract: no single-iPhone regressions.

These checks verify source policy and ABI profiles, not device-side exploits.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class CompatibilityIOS16Through18Tests(unittest.TestCase):
    def test_future_cpu_families_do_not_use_an_uninitialized_string(self):
        exploit = (ROOT / "Application/Dopamine/Jailbreak/DOExploit.m").read_text()
        match = exploit.split('sysctlbyname("hw.cpufamily"', 1)[1].split("char OSVersionString", 1)[0]
        self.assertIn("NSString *thisCPU = nil;", match)
        self.assertIn("default:", match)
        # Unknown chip families can still match a specifically listed device,
        # but must never impersonate an A17 or match any other CPU family.
        self.assertIn("thisCPU && [supportedDevice isEqualToString:thisCPU]", exploit)
        self.assertIn("thisCPU && [device isEqualToString:thisCPU]", exploit)

    def test_kernel_build_string_is_terminated_on_error_or_truncation(self):
        exploit = (ROOT / "Application/Dopamine/Jailbreak/DOExploit.m").read_text()
        support = exploit.split('char OSVersionString[64]', 1)[1].split('NSString *thisIOSVersion', 1)[0]
        self.assertIn('OSVersionString[sizeof(OSVersionString) - 1] =', support)

    def test_actual_profile_covers_16_17_18_without_guessing_newer_os(self):
        compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        if not compiler:
            self.skipTest("C compiler unavailable")
        header = ROOT / "Application/Dopamine/Jailbreak/RootHideBootstrapProfile.h"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "compat.c"
            executable = Path(directory) / "compat.exe"
            path.write_text('#include "' + header.as_posix() + '"\n'
                            'int main(void) {\n'
                            ' for (int os=16; os<=18; ++os)\n'
                            '   if (rh3_bootstrap_version_for_os(os)!=1900) return os;\n'
                            ' if (rh3_bootstrap_version_for_os(19)!=0) return 19;\n'
                            ' return 0;\n}\n', encoding="utf-8")
            compiled = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                       str(path), "-o", str(executable)],
                                      capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_exploit_preflight_does_not_single_out_iphone_x_or_arm64(self):
        env = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text()
        is_supported = env.split("- (BOOL)isSupported", 1)[1].split("- (BOOL)deviceSupportsFaceID", 1)[0]
        self.assertIn("EXPLOIT_TYPE_KERNEL", is_supported)
        self.assertIn("EXPLOIT_TYPE_PAC", is_supported)
        self.assertIn("EXPLOIT_TYPE_PPL", is_supported)
        self.assertIn("isPACBypassRequired", is_supported)
        self.assertIn("isPPLBypassRequired", is_supported)
        self.assertNotIn("iPhone10,3", is_supported)

        jailbreaker = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text()
        preflight = jailbreaker.split("- (NSError *)rootHidePreflightError", 1)[1].split("- (void)runWithError:", 1)[0]
        self.assertIn("rh3_bootstrap_version_for_os((int)os.majorVersion)", preflight)
        self.assertIn("[environment isSupported]", preflight)
        self.assertNotIn("isArm64e", preflight)
        self.assertNotIn("iPhone10,3", preflight)

    def test_runtime_preserves_software_and_kernel_architectures(self):
        systemhook = (ROOT / "BaseBin/systemhook/Makefile").read_text()
        self.assertIn("-arch arm64 -arch arm64e", systemhook)
        main = (ROOT / "BaseBin/systemhook/src/main.c").read_text()
        self.assertIn("__builtin_available(iOS 18.0, *)", main)
        self.assertIn("#ifndef __arm64e__", main)
        dyld_hook = (ROOT / "BaseBin/dyldhook/src/roothider.c").read_text()
        self.assertIn("#if IOS <= 18", dyld_hook)
        profile = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text()
        self.assertIn("!version || ![[DOEnvironmentManager sharedManager] isSupported]", profile)

    def test_readme_distinguishes_support_from_device_validation(self):
        readme = (ROOT / "README.md").read_text()
        for text in ("## Compatibilidad", "(arm64)", "(arm64e)", "A18",
                     "iOS 16", "iOS 17", "iOS 18", "exploits", "experimental"):
            self.assertIn(text, readme)
        self.assertTrue((ROOT / "docs/COMPATIBILITY-IOS16-18.md").is_file())


if __name__ == "__main__":
    unittest.main()
