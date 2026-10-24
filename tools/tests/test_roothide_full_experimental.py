"""Contracts for the complete but fail-closed RootHide 3 app variant."""
import io
import plistlib
from pathlib import Path
import unittest
import zipfile
from tools.verify_roothide_full_experimental import (
    check_full_identity, GUARD_MARKER, DISABLED_MARKER, ACTIVE_MARKER,
    TWEAKS_ON_MARKER, TWEAKS_SAFE_MARKER, ALL_ENABLED_DISPLAY_NAME,
    EXPERIMENTAL_BUNDLE_ID, EXPERIMENTAL_DISPLAY_NAME,
    HARDWARE_BETA_BUNDLE_ID, HARDWARE_BETA_DISPLAY_NAME
)
from tools.tests.test_verify_roothide_build import thin_macho

ROOT = Path(__file__).resolve().parents[2]


def source(name):
    return (ROOT / name).read_text(encoding="utf-8")


def fixture(*, identifier=EXPERIMENTAL_BUNDLE_ID, display=EXPERIMENTAL_DISPLAY_NAME,
            marker=True, hardware_beta=False, all_enabled=False, extra=None):
    memory = io.BytesIO()
    info = plistlib.dumps({"CFBundleIdentifier": identifier,
                           "CFBundleDisplayName": display,
                           "CFBundleExecutable": "Dopamine"})
    with zipfile.ZipFile(memory, "w") as archive:
        archive.writestr("Payload/Dopamine.app/Info.plist", info)
        archive.writestr("Payload/Dopamine.app/Dopamine",
                         thin_macho() + (GUARD_MARKER if marker else b"") +
                         (ACTIVE_MARKER if hardware_beta else DISABLED_MARKER) +
                         ((TWEAKS_ON_MARKER if all_enabled else TWEAKS_SAFE_MARKER)
                          if hardware_beta else b""))
        if extra:
            archive.writestr(extra, b"x")
    memory.seek(0)
    return memory


class FullExperimentalTests(unittest.TestCase):
    def test_duplicate_identifiers_in_built_frameworks_are_rejected(self):
        memory = fixture()
        with zipfile.ZipFile(memory, "a") as archive:
            for framework in ("Titan", "kfd"):
                archive.writestr(f"Payload/Dopamine.app/Frameworks/{framework}.framework/Info.plist",
                                 plistlib.dumps({"CFBundleIdentifier": EXPERIMENTAL_BUNDLE_ID}))
        with zipfile.ZipFile(memory) as archive:
            errors, details = check_full_identity(archive)
        self.assertTrue(any("DuplicateIdentifier" in error for error in errors))
        self.assertEqual(len(details["bundle_identifiers"]), 3)

    def test_unique_identifiers_and_nested_framework_duplicates(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                memory = fixture()
                with zipfile.ZipFile(memory, "a") as archive:
                    for i, path in enumerate(("Titan.framework", "Titan.framework/Frameworks/Nested.framework")):
                        archive.writestr("Payload/Dopamine.app/Frameworks/" + path + "/Info.plist",
                                         plistlib.dumps({"CFBundleIdentifier": f"com.test.framework{0 if duplicate else i}"}))
                with zipfile.ZipFile(memory) as archive:
                    errors, _ = check_full_identity(archive)
                self.assertEqual(bool(errors), duplicate)

    def test_missing_and_unresolved_framework_identifiers_are_rejected(self):
        for value in (None, "", "$(PRODUCT_BUNDLE_IDENTIFIER)", 42):
            with self.subTest(value=value):
                memory = fixture()
                with zipfile.ZipFile(memory, "a") as archive:
                    archive.writestr("Payload/Dopamine.app/Frameworks/Titan.framework/Info.plist",
                                     plistlib.dumps({} if value is None else {"CFBundleIdentifier": value}))
                with zipfile.ZipFile(memory) as archive:
                    self.assertTrue(check_full_identity(archive)[0])

    def test_distinct_identity_and_guards_in_build_configuration(self):
        make = source("Application/Makefile")
        self.assertIn("ROOTHIDE_EXPERIMENT_ID := " + EXPERIMENTAL_BUNDLE_ID, make)
        self.assertIn("ROOTHIDE_EXPERIMENT_NAME := RootHide 3 Experimental", make)
        self.assertIn("RH3_FULL_APP_EXPERIMENTAL=1 ROOTHIDE3_BOOTSTRAP_READY=$(ROOTHIDE_BOOTSTRAP_GATE)", make)
        self.assertIn("Dopamine/Dopamine.entitlements", make)
        self.assertIn("ROOTHIDE_EXPERIMENTAL_BUILD", source(".github/workflows/main.yml"))
        self.assertIn("RootHide3-Full-Experimental.ipa", source(".github/workflows/main.yml"))
        self.assertIn("RH3_FULL_APP_EXPERIMENTAL_GUARDED_V1", source("Application/Dopamine/main.m"))

    def test_no_unprotected_stock_bootstrap_fallback_or_trollstore_cli(self):
        jb = source("Application/Dopamine/Jailbreak/DOJailbreaker.m")
        section = jb[jb.index("- (void)runWithError:"):jb.index("[self gatherSystemInformation]")]
        self.assertIn("#if RH3_FULL_APP_EXPERIMENTAL", section)
        self.assertIn("if (![DOBootstrapper rootHidePortEnabled])", section)
        self.assertIn("return;", section)
        self.assertLess(section.index("if (![DOBootstrapper rootHidePortEnabled])"),
                        section.index("BOOL removeJailbreakEnabled"))
        main = source("Application/Dopamine/main.m")
        self.assertIn("#if !RH3_INSTALLABLE_DIAGNOSTIC && !RH3_FULL_APP_EXPERIMENTAL", main)
        bootstrap = source("Application/Dopamine/Jailbreak/DOBootstrapper.m")
        self.assertIn("#define ROOTHIDE3_BOOTSTRAP_READY 0", bootstrap)

    def test_ui_shows_experiment_but_restricts_lifecycle(self):
        ui = source("Application/Dopamine/UI/DOMainViewController.m")
        self.assertIn("Full Dopamine test build. Jailbreak disabled", ui)
        self.assertIn("self.jailbreakBtn.enabled = self.jailbreakBtn.enabled &&", ui)
        self.assertIn("if (![DOBootstrapper rootHidePortEnabled]) return;", ui)
        self.assertIn('isEqualToString:@"reboot-userspace"])) return NO;', ui)
        self.assertIn("#if !RH3_FULL_APP_EXPERIMENTAL", ui)

    def test_checker_distinguishes_valid_identity_and_rejects_unsafe_content(self):
        with zipfile.ZipFile(fixture()) as archive:
            errors, details = check_full_identity(archive)
            self.assertEqual(errors, [])
            self.assertEqual(details["bundle_id"], EXPERIMENTAL_BUNDLE_ID)
            self.assertRegex(details["executable_sha256"], r"^[a-f0-9]{64}$")
        for args in ({"identifier": "com.opa334.Dopamine"},
                     {"marker": False},
                     {"extra": "Payload/Bad.app/extra"},
                     {"extra": "Payload/Dopamine.app/../escape"}):
            with self.subTest(args=args), zipfile.ZipFile(fixture(**args)) as archive:
                self.assertTrue(check_full_identity(archive)[0])

    def test_hardware_beta_identity_and_marker_never_confused_with_safe_build(self):
        memory = fixture(identifier=HARDWARE_BETA_BUNDLE_ID,
                         display=HARDWARE_BETA_DISPLAY_NAME, hardware_beta=True)
        with zipfile.ZipFile(memory) as archive:
            self.assertEqual(check_full_identity(archive, hardware_beta=True)[0], [])
            self.assertTrue(check_full_identity(archive, hardware_beta=False)[0])
        with zipfile.ZipFile(fixture()) as archive:
            self.assertTrue(check_full_identity(archive, hardware_beta=True)[0])

    def test_all_enabled_beta_requires_both_distinct_markers(self):
        memory = fixture(identifier=HARDWARE_BETA_BUNDLE_ID,
                         display=ALL_ENABLED_DISPLAY_NAME,
                         hardware_beta=True, all_enabled=True)
        with zipfile.ZipFile(memory) as archive:
            self.assertEqual(check_full_identity(archive, hardware_beta=True,
                                                all_enabled=True)[0], [])
            self.assertTrue(check_full_identity(archive, hardware_beta=True)[0])
            self.assertTrue(check_full_identity(archive, all_enabled=True)[0])
        memory = fixture(identifier=HARDWARE_BETA_BUNDLE_ID,
                         display=ALL_ENABLED_DISPLAY_NAME,
                         hardware_beta=True, all_enabled=False)
        with zipfile.ZipFile(memory) as archive:
            self.assertTrue(check_full_identity(archive, hardware_beta=True,
                                                all_enabled=True)[0])

    def test_first_boot_opt_in_does_not_erase_prior_safe_mode(self):
        jb = source("Application/Dopamine/Jailbreak/DOJailbreaker.m")
        first = jb[jb.index('if (!installed) {', jb.index('BOOL safeModeAlreadyExists')):
                   jb.index('launchd: allocating boomerang port')]
        self.assertIn('#if ROOTHIDE3_TWEAKS_DEFAULT_ON', first)
        self.assertIn('safeModeAlreadyExists', first)
        self.assertIn('#else', first)
        self.assertIn('writeToFile:safeMode', first)
        self.assertNotIn('removeItemAtPath:safeMode', first)
        self.assertNotIn('unlink(safeMode', first)
        self.assertIn('watchdog still authoritative', first)
        self.assertIn('DISABLE_TWEAKS', source("BaseBin/systemhook/src/main.c"))
        self.assertIn('.roothide3-watchdog-safe-mode', source("BaseBin/systemhook/src/main.c"))


if __name__ == "__main__":
    unittest.main()
