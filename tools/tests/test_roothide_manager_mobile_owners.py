"""Exercise RootHide's shipped UID501 app payload ownership contract.

This prevents an all-root backlink walk from rejecting official pinned debs.
Native execution on iOS remains separately necessary.
"""
import io
import lzma
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
import unittest

from test_roothide_managers_r173 import deb_members

ROOT = Path(__file__).resolve().parents[2]


def app_owners(filename, bundle):
    blob = (ROOT / "Application/Dopamine/Resources" / filename).read_bytes()
    members = deb_members(blob)
    name = next(n for n in members if n.startswith("data.tar."))
    payload = lzma.decompress(members[name]) if name.endswith(".lzma") else members[name]
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
        found = {}
        expected = ("Applications", f"Applications/{bundle}.app",
                    f"Applications/{bundle}.app/Info.plist",
                    f"Applications/{bundle}.app/{bundle}")
        for entry in archive:
            path = entry.name.removeprefix("./").rstrip("/")
            if path in expected:
                found[path] = (entry.uid, entry.mode)
        return found


class MobileOwnedBundleBacklinks(unittest.TestCase):
    def test_pinned_debs_reproduce_mixed_package_owners(self):
        for package, app, owner in (("roothide_sileo.deb", "Sileo", 0),
                                    ("roothide_zebra.deb", "Zebra", 501),
                                    ("roothideapp.deb", "RootHide", 501)):
            with self.subTest(package=package):
                owners = app_owners(package, app)
                self.assertEqual(len(owners), 4)
                self.assertEqual({uid for uid, _ in owners.values()}, {owner})
                self.assertFalse(any(mode & 0o22 for _, mode in owners.values()))

    def test_c_policy_only_accepts_mobile_for_exact_vendor_apps(self):
        compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        if not compiler:
            self.skipTest("C compiler unavailable")
        header = ROOT / "Application/Dopamine/Jailbreak/RootHideAppOwnerPolicy.h"
        self.assertTrue(header.is_file())
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory) / "policy.c"
            out = Path(directory) / "policy.exe"
            src.write_text('#include "' + header.as_posix() + '"\n'
                           'int main(void) {\n'
                           ' if(!rh3_apps_directory_owner_allowed(0,0,0755))return 1;\n'
                           ' if(!rh3_apps_directory_owner_allowed(501,0,0755))return 2;\n'
                           ' if(rh3_apps_directory_owner_allowed(502,0,0755))return 3;\n'
                           ' if(rh3_apps_directory_owner_allowed(501,0,0777))return 4;\n'
                           ' if(!rh3_bundle_owner_allowed("Zebra.app",501,0))return 5;\n'
                           ' if(!rh3_bundle_owner_allowed("RootHide.app",501,0))return 6;\n'
                           ' if(rh3_bundle_owner_allowed("Sileo.app",501,0))return 7;\n'
                           ' if(rh3_bundle_owner_allowed("Other.app",501,0))return 8;\n'
                           ' if(rh3_bundle_owner_allowed("RootHide.app.evil",501,0))return 9;\n'
                           ' if(!rh3_bundle_owner_allowed("Other.app",0,0))return 10;\n'
                           ' if(!rh3_app_descendant_owner_allowed(1,501,0))return 11;\n'
                           ' if(rh3_app_descendant_owner_allowed(0,501,0))return 12;\n'
                           ' if(rh3_app_descendant_owner_allowed(1,502,0))return 13;\n'
                           ' return 0;\n}\n', encoding="utf-8")
            built = subprocess.run([compiler, "-std=c11", "-Wall", "-Werror",
                                    str(src), "-o", str(out)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            executed = subprocess.run([str(out)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stderr)

    def test_backlink_walk_keeps_trusted_app_owner_distinct_from_symlink_owner(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/RootHideAppLinks.h").read_text()
        self.assertIn('RootHideAppOwnerPolicy.h', source)
        self.assertIn('rh3_apps_directory_owner_allowed', source)
        self.assertIn('rh3_bundle_owner_allowed', source)
        self.assertIn('rh3_app_descendant_owner_allowed', source)
        self.assertIn('RH3AppBacklink(fd, depth, owner)', source)
        self.assertIn('AT_SYMLINK_NOFOLLOW', source)
        self.assertIn('O_NOFOLLOW', source)

    def test_bundled_app_inventory_uses_verified_mobile_owner_without_forging_root(self):
        src = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text()
        inventory = src.split('static void RH3RecordInstalledAppInventory', 1)[1].split('- (NSError *)repairRootHideAppLinks', 1)[0]
        self.assertIn('rh3_bundle_owner_allowed', inventory)
        self.assertIn('S_ISREG(plistInfo.st_mode)', inventory)
        self.assertNotIn('plistInfo.st_uid == 0', inventory)

    def test_stale_launchservices_registration_checks_pinned_mobile_owned_bundles(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text()
        apps = source.split('NSString *oldRoot = RH3StaleRegisteredRoot(', 1)[1].split(
            'return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps', 1)[0]
        self.assertIn('rh3_apps_directory_owner_allowed(appsInfo.st_uid, 0, appsInfo.st_mode)', apps)
        self.assertIn('rh3_bundle_owner_allowed(expected.lastPathComponent.UTF8String, appInfo.st_uid, 0)', apps)
        self.assertIn('rh3_bundle_owner_allowed(expected.lastPathComponent.UTF8String, plistInfo.st_uid, 0)', apps)
        self.assertIn('oldError == ENOENT', apps)

    def test_initial_manager_registration_is_explicit_and_bounded(self):
        src = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text()
        routine = src.split('static NSError *RH3RegisterPinnedJailbreakApps(', 1)[1].split(
            'static void RH3RecordInstalledAppInventory(', 1)[0]
        self.assertIn('rh3_bundle_owner_allowed', routine)
        self.assertIn('"-p"', routine)
        self.assertIn('RH3WaitForBootstrapChild(child, 30)', routine)
        self.assertIn('dispatch_group_wait(', routine)
        self.assertIn('jbclient_trust_file_by_path(', routine)
        self.assertIn('"RootHide"', routine)
        finalize = src.split('- (NSError *)finalizeRootHideBootstrap\n{', 1)[1].split(
            '- (NSError *)deleteRootHideBootstrap\n{', 1)[0]
        self.assertLess(finalize.index('repairRootHideAppLinks'),
                        finalize.index('RH3RegisterPinnedJailbreakApps(root)'))
        self.assertLess(finalize.index('RH3RegisterPinnedJailbreakApps(root)'),
                        finalize.index('writeToFile:marker'))
        self.assertIn('if (!installed)', finalize)


if __name__ == "__main__":
    unittest.main()
