"""r218: exit-0 uicache -p did not produce installed LS proxies.

All checks are host-side evidence or source contracts. They do not certify
the installed iPhone's metadata, permissions, lsd state or private API behavior.
"""

import io
from pathlib import Path
import plistlib
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BOOT = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(encoding="utf-8")
HEADER = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.h").read_text(encoding="utf-8")
UI = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m").read_text(encoding="utf-8")
ENV = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(encoding="utf-8")
SDK_WORKSPACE = (ROOT / "BaseBin/_external/include/CoreServices/LSApplicationWorkspace.h").read_text()


def deb_members(filename):
    data = filename.read_bytes()
    assert data.startswith(b"!<arch>\n")
    offset = 8
    while offset < len(data):
        header = data[offset:offset + 60]
        name = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58])
        offset += 60
        yield name, data[offset:offset + size]
        offset += size + size % 2


class LaunchServicesR218Tests(unittest.TestCase):
    def test_bundled_manager_identifiers_and_app_types_are_actually_correct(self):
        # Verify real .deb data.tar, not a guessed ID from Objective-C source.
        expected = {
            "roothide_sileo.deb": ("Sileo", "org.coolstar.SileoStore"),
            "roothide_zebra.deb": ("Zebra", "xyz.willy.Zebra"),
            "roothideapp.deb": ("RootHide", "com.roothide.manager"),
        }
        for package, (name, identifier) in expected.items():
            with self.subTest(package=package):
                archive = ROOT / "Application/Dopamine/Resources" / package
                members = list(deb_members(archive))
                tar = next(data for entry, data in members if entry.startswith("data.tar"))
                with tarfile.open(fileobj=io.BytesIO(tar), mode="r:*") as bundle:
                    plist = next(m for m in bundle if m.name.lstrip("./") == f"Applications/{name}.app/Info.plist")
                    info = plistlib.loads(bundle.extractfile(plist).read())
                    self.assertEqual(info["CFBundleIdentifier"], identifier)
                    self.assertEqual(info["CFBundlePackageType"], "APPL")
                    self.assertEqual(info["CFBundleExecutable"], name)

    def test_registration_returns_zero_without_ls_acknowledgment(self):
        register = BOOT.split("static NSError *RH3RegisterPinnedJailbreakApps(", 1)[1].split(
            "static void RH3RecordInstalledAppInventory(", 1
        )[0]
        self.assertIn('"-p", app.fileSystemRepresentation', register)
        self.assertIn('RH3WaitForBootstrapChild(child, 30)', register)
        self.assertNotIn("LSApplicationWorkspace", register)
        self.assertNotIn("registerApplicationDictionary", register)
        self.assertNotIn("applicationProxyForIdentifier:", register)
        refresh = ENV.split("- (int)refreshJailbreakApps", 1)[1].split("- (void)", 1)[0]
        self.assertIn('arguments:@[@"-p", path]', refresh)
        self.assertIn("if (!result) refreshed++", refresh)
        self.assertNotIn("verifyExplicitRootHideAppRefresh", refresh)

    def test_query_surface_api_checked_against_local_sdk_header(self):
        self.assertIn("enumerateApplicationsOfType:(NSUInteger)type block:", SDK_WORKSPACE)
        diagnostic = BOOT.split("static NSDictionary<NSString *, NSNumber *> *RH3ObserveLSQuerySurfaces(", 1)[1].split(
            "+ (void)recordRootHideLaunchServicesDifferentialWithContext:", 1
        )[0]
        self.assertIn('NSClassFromString(@"LSApplicationWorkspace")', diagnostic)
        self.assertIn('NSSelectorFromString(@"enumerateApplicationsOfType:block:")', diagnostic)
        self.assertIn("respondsToSelector:iterator", diagnostic)
        self.assertIn('applicationIdentifier', diagnostic)
        self.assertIn('bundleIdentifier', diagnostic)
        self.assertIn('@"com.apple.Preferences"', diagnostic)
        self.assertIn('workspace_type', diagnostic)
        self.assertIn("enumerated >= 2048", diagnostic)
        self.assertIn("@catch", diagnostic)
        self.assertNotIn('NSSelectorFromString(@"registerApplication', diagnostic)
        self.assertNotIn("unregisterApplication", diagnostic)

    def test_plist_observation_is_bounded_nofollow_readonly_and_never_trusts_inaccessible(self):
        fn = BOOT.split("static int RH3ObserveLSBundlePlist(", 1)[1].split(
            "static NSDictionary<NSString *, NSNumber *> *RH3ObserveLSQuerySurfaces(", 1
        )[0]
        for term in ("rootHideBrandForPath:root", "lstat(", "O_NOFOLLOW",
                     "fstat(", "st_ino == before.st_ino", "pread(",
                     "NSPropertyListSerialization", "CFBundleIdentifier",
                     "CFBundlePackageType", 'return classification;'):
            self.assertIn(term, fn)
        self.assertIn("return -1", fn)
        self.assertIn("classification = 2", fn)
        self.assertNotIn("chmod(", fn)
        self.assertNotIn("chown(", fn)
        self.assertNotIn("write(", fn)

    def test_readonly_differential_runs_once_per_diagnostic_without_retrying_uicache(self):
        collector = BOOT.split("+ (void)recordRootHideLaunchServicesDifferentialWithContext:", 1)[1].split(
            "- (NSError *)repairRootHideAppLinks", 1
        )[0]
        for must in ("JBS_SYSTEMWIDE_GET_JBROOT", "RH3ObserveLSQuerySurfaces(",
                     "RH3ObserveLSBundlePlist(", "3 * NSEC_PER_SEC",
                     "root_known", "system_control_installed",
                     "own_app_control_installed", "workspace_available",
                     "workspace_id_seen", "workspace_path_seen"):
            self.assertIn(must, collector)
        for forbidden in ("exec_cmd(", "posix_spawn(", "trust_file(", "installPackage",
                          "unregisterApplication", "registerApplicationDictionary",
                          "killall(", "rebootUserspace", "writeToFile:"):
            self.assertNotIn(forbidden, collector)
        self.assertIn("+ (void)recordRootHideLaunchServicesDifferentialWithContext:", HEADER)
        full = UI.split("- (void)diagnoseRootHideAllPressed", 1)[1].split(
            "- (void)diagnoseRootHideRuntimePressed", 1
        )[0]
        self.assertLess(full.index("diagnoseRootHideComprehensive]"),
                        full.index('recordRootHideLaunchServicesDifferentialWithContext:@"full-diagnostic"'))
        self.assertLess(full.index('recordRootHideLaunchServicesDifferentialWithContext:@"full-diagnostic"'),
                        full.index("rh3FinishUnifiedReportWithResult:result]"))
        refresh = UI.split("- (void)refreshJailbreakAppsPressed", 1)[1].split(
            "- (void)repairRootHideLibkrwPressed", 1
        )[0]
        self.assertEqual(refresh.count('recordRootHideLaunchServicesDifferentialWithContext:@"after-explicit-refresh"'), 1)
        self.assertIn("if (result != ETIMEDOUT)", refresh)
        self.assertLess(refresh.index('recordRootHideLaunchServicesSnapshotWithContext:@"after-explicit-refresh"'),
                        refresh.index('recordRootHideLaunchServicesDifferentialWithContext:@"after-explicit-refresh"'))


if __name__ == "__main__":
    unittest.main()
