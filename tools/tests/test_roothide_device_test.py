"""Fail-closed contracts for the independently installable GUI-only IPA.

These tests do not prove iOS will accept an ad-hoc signature on a given
device; the test IPA requires a suitable installation/signing mechanism.
"""

import plistlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


def source(name):
    return (ROOT / name).read_text(encoding="utf-8")


class DeviceTestContractTests(unittest.TestCase):
    def test_identity_is_separate_and_unsigned_privileges_absent(self):
        make = source("Application/Makefile")
        self.assertIn("PRODUCT_BUNDLE_IDENTIFIER=com.gokuencinar.roothide3.diagnostic", make)
        self.assertIn("INFOPLIST_KEY_CFBundleDisplayName='RootHide 3 Test'", make)
        self.assertIn("RH3_INSTALLABLE_DIAGNOSTIC=1 ROOTHIDE3_BOOTSTRAP_READY=0", make)
        self.assertIn("build-diagnostic", make)
        self.assertIn("RootHide3-Device-Test.ipa", make)
        self.assertIn("ldid -SDopamine/Diagnostic.entitlements", make)
        self.assertNotIn("ldid -SDopamine/Dopamine.entitlements build-diagnostic", make)
        entitlements = plistlib.loads((ROOT / "Application/Dopamine/Diagnostic.entitlements").read_bytes())
        self.assertEqual(entitlements, {})

    def test_device_test_does_not_ship_jailbreak_installers(self):
        make = source("Application/Makefile")
        self.assertIn("Dopamine.app/basebin.tar", make)
        self.assertIn("Dopamine.app/*.deb", make)
        self.assertIn("Dopamine.app/*.tar.zst", make)

    def test_device_test_ui_omits_jailbreak_settings_restart_and_update(self):
        view = source("Application/Dopamine/UI/DOMainViewController.m")
        start = view.index("-(void)setupStack")
        diagnostic = view.index("#if RH3_INSTALLABLE_DIAGNOSTIC", start)
        normal = view.index("UIStackView *stackView =", diagnostic)
        isolated = view[diagnostic:normal]
        self.assertIn("RootHide 3 — Device Test", isolated)
        self.assertIn("RootHide installation, jailbreak, kernel patches", isolated)
        self.assertIn("return;", isolated)
        self.assertIn("#endif", isolated)
        self.assertNotIn("startJailbreak", isolated)
        self.assertNotIn("DOSettingsController alloc", isolated)

    def test_direct_jailbreak_and_reboot_calls_are_also_disabled(self):
        source_text = source("Application/Dopamine/Jailbreak/DOJailbreaker.m")
        start = source_text.index("- (void)runWithError:")
        guarded = source_text[start:source_text.index("#endif // RH3_INSTALLABLE_DIAGNOSTIC", start)]
        self.assertIn("#if RH3_INSTALLABLE_DIAGNOSTIC", guarded)
        self.assertIn("return;", guarded)
        self.assertIn("#else", guarded)
        self.assertLess(guarded.index("return;"), guarded.index("[self doExploitation]"))
        finalize = source_text[source_text.index("- (void)finalize\n"):]
        self.assertIn("#if RH3_INSTALLABLE_DIAGNOSTIC", finalize)
        self.assertLess(finalize.index("return;"), finalize.index("rebootUserspace"))
        bootstrap = source("Application/Dopamine/Jailbreak/DOBootstrapper.m")
        self.assertIn("#define ROOTHIDE3_BOOTSTRAP_READY 0", bootstrap)

    def test_ci_artifact_keeps_diagnostic_separate_from_root_hide(self):
        workflow = source(".github/workflows/main.yml")
        self.assertIn("RootHide3-Device-Test-APP-ONLY", workflow)
        self.assertIn("gmake -C Application diagnostic", workflow)
        self.assertIn("RootHide3-Device-Test.ipa", workflow)
        self.assertIn("RootHide3-COMPILE-ONLY-NOT-FOR-INSTALL", workflow)
        self.assertIn("python3 tools/roothide_port_audit.py --strict", workflow)


if __name__ == "__main__":
    unittest.main()
