"""The hardware beta must reject unsupported/previously jailbroken devices."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RootHideHardwarePreflightTests(unittest.TestCase):
    def test_preflight_before_kernel_exploit(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text(encoding="utf-8")
        entry = source[source.index("- (void)runWithError:"):
                       source.index("[self gatherSystemInformation]")]
        self.assertIn("if (![DOBootstrapper rootHidePortEnabled])", entry)
        self.assertIn("NSError *preflightError = [self rootHidePreflightError]", entry)
        preflight = source.split("- (NSError *)rootHidePreflightError", 1)[1].split("- (void)runWithError:", 1)[0]
        self.assertIn("NSProcessInfo.processInfo.operatingSystemVersion", preflight)
        self.assertIn("os.majorVersion < 15 || os.majorVersion > 16", preflight)
        self.assertIn("isArm64e", preflight)
        self.assertIn("isSupported", preflight)
        self.assertIn("isJailbrokenWithOtherJailbreak", preflight)
        self.assertIn("[[DOBootstrapper new] rootHidePreflightError]", preflight)

    def test_ui_preflight_precedes_even_the_memory_workaround(self):
        source = (ROOT / "Application/Dopamine/UI/DOMainViewController.m").read_text(encoding="utf-8")
        start = source.split("- (void)startJailbreak", 1)[1]
        self.assertLess(start.index("[jailbreaker rootHidePreflightError]"),
                        start.index("[jailbreaker contiguousMappingWorkaroundNeeded]"))
        rejection = start.split("if (preflightError)", 1)[1].split("#endif", 1)[0]
        self.assertIn("return;", rejection)
        self.assertNotIn("reboot", rejection.lower())

    def test_preflight_checks_assets_and_existing_state_without_mutation(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(encoding="utf-8")
        preflight = source.split("- (NSError *)rootHidePreflightError", 1)[1].split("- (NSError *)rh3BuildPackageSourcesInRoot:", 1)[0]
        self.assertIn('lstat("/var/jb", &visibleRoot)', preflight)
        self.assertIn("errno != ENOENT", preflight)
        self.assertIn("rootHideExistingRootWithError:&error", preflight)
        self.assertIn("RH3CheckInterruptedOperations(root)", preflight)
        self.assertIn('stage isEqualToString:@"running-script"', preflight)
        self.assertIn("rh3VerifyAssetsForVersion:version", preflight)
        for mutation in ("removeItemAtPath:", "moveItemAtPath:", "writeToFile:", "exec_cmd"):
            self.assertNotIn(mutation, preflight)

    def test_hardware_ci_requires_explicit_manual_input(self):
        workflow = (ROOT / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.hardware_beta == true", workflow)
        self.assertIn("default: false", workflow)
        self.assertIn("--hardware-beta --ipa Application/RootHide3-Hardware-Beta.ipa", workflow)
        self.assertIn("RootHide3-HARDWARE-BETA-JAILBREAK-ENABLED", workflow)
        self.assertIn("python3 tools/roothide_port_audit.py --strict", workflow)

    def test_trollstore_platform_entitlement_not_equated_with_jailbreak(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(encoding="utf-8")
        method = source[source.index("- (BOOL)isJailbrokenWithOtherJailbreak"):
                        source.index("- (NSString *)jailbrokenVersion")]
        self.assertIn("if ([DOBootstrapper rootHidePortEnabled])", method)
        self.assertIn("return otherJailbreakActived(false);", method)
        self.assertLess(method.index("return otherJailbreakActived(false)"),
                        method.index("if (csFlags & CS_PLATFORM_BINARY)"))


if __name__ == "__main__":
    unittest.main()
