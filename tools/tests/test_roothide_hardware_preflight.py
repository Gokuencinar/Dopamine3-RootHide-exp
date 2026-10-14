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
        self.assertIn("NSProcessInfo.processInfo.operatingSystemVersion", entry)
        self.assertIn("os.majorVersion < 15 || os.majorVersion > 16", entry)
        self.assertIn("isArm64e", entry)
        self.assertIn("isJailbrokenWithOtherJailbreak", entry)

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
