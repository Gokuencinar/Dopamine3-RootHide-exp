"""Source-level regressions for RootHide3 manager packages and app sources.

The Windows test host cannot execute Foundation/dpkg/launchd. These checks
verify mutation boundaries in the production Objective-C implementation;
actual manager launch and icon registration still require iOS hardware.
"""

from pathlib import Path
from io import BytesIO
import hashlib
import lzma
import plistlib
import re
import tarfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(
    encoding="utf-8"
)
ENVIRONMENT = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(
    encoding="utf-8"
)


def method(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin:source.index(end, begin + len(start))]


def deb_members(blob: bytes) -> dict[str, bytes]:
    """Read a local Debian ar archive without running package scripts."""
    if not blob.startswith(b"!<arch>\n"):
        raise ValueError("Not a Debian ar archive")
    members = {}
    position = 8
    while position < len(blob):
        header = blob[position:position + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise ValueError("Truncated or malformed ar header")
        name = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58].decode("ascii").strip())
        start = position + 60
        end = start + size
        if end > len(blob) or name in members:
            raise ValueError("Truncated or duplicate ar member")
        members[name] = blob[start:end]
        position = end + (size % 2)
    return members


def tar_entries(members: dict[str, bytes], prefix: str):
    name = next((name for name in members if name.startswith(prefix + ".tar.")), None)
    if name is None:
        raise ValueError("Missing archive member " + prefix)
    content = members[name]
    if name.endswith(".lzma"):
        content = lzma.decompress(content)
    with tarfile.open(fileobj=BytesIO(content), mode="r:*") as archive:
        return {
            item.name.removeprefix("./"): archive.extractfile(item).read()
            for item in archive
            if item.isfile()
        }


class ManagerLifecycleR173(unittest.TestCase):
    def test_sources_are_initialized_only_in_new_or_verified_recovered_root(self):
        """Re-jailbreaking an installed root must preserve custom APT/Zebra repos."""
        create = method(BOOTSTRAP, "- (NSError *)rh3CreateRoot:", "// Recover only the verified")
        recover = method(BOOTSTRAP, "- (NSError *)rh3RecoverTmpCollisionAtRoot:",
                         "- (NSError *)rh3RerandomizeRoot:")
        prepare = method(BOOTSTRAP, "- (void)prepareRootHideBootstrapWithCompletion:(void (^)(NSError *))completion\n{",
                         "- (NSArray<NSString *> *)rootHideSelectedManagerPackagesWithError:")
        finalize = method(BOOTSTRAP, "- (NSError *)finalizeRootHideBootstrap\n{",
                          "- (NSError *)deleteRootHideBootstrap\n{")
        source_call = "[self rh3BuildPackageSourcesInRoot:root version:version]"

        self.assertEqual(create.count(source_call), 1)
        self.assertEqual(recover.count(source_call), 1)
        self.assertNotIn(source_call, prepare)
        self.assertNotIn(source_call, finalize)
        self.assertLess(create.index("RH3PrepareMobileHomeAtRoot(root)"),
                        create.index(source_call))
        self.assertLess(recover.index("RH3IsKnownTmpCollision(root, secondary)"),
                        recover.index(source_call))
        # No third call is allowed elsewhere; it could mutate installed sources.
        self.assertEqual(BOOTSTRAP.count(source_call), 2)

    def test_sources_preserve_default_repositories_only_in_initialization(self):
        sources = method(BOOTSTRAP, "- (NSError *)rh3BuildPackageSourcesInRoot:",
                         "- (BOOL)rh3ReplaceSymlinkAtPath:")
        self.assertIn('@"etc/apt/sources.list"', sources)
        self.assertIn('@"etc/apt/sources.list.d/procursus.sources"', sources)
        self.assertIn('@"default.sources"', sources)
        self.assertIn('@"sources.list"', sources)
        self.assertIn('@"var/mobile/Library/Application Support/xyz.willy.Zebra"', sources)
        self.assertIn('![fm removeItemAtPath:sourcePath error:&error]', sources)

    def test_manager_debs_are_pinned_and_unknown_selection_fails_closed(self):
        assets = method(BOOTSTRAP, "- (NSError *)rh3VerifyAssetsForVersion:",
                        "- (NSError *)rootHidePreflightError")
        picker = method(BOOTSTRAP, "- (NSArray<NSString *> *)rootHideSelectedManagerPackagesWithError:",
                        "- (NSString *)rootHideManagerPackageWithError:")
        install = method(BOOTSTRAP, "- (NSError *)installPackageManagers",
                         "- (BOOL)shouldInstallPackage:")
        for package in ("roothide_sileo.deb", "roothide_zebra.deb", "roothideapp.deb"):
            self.assertIn('@"' + package + '": @"', assets)
        self.assertIn('isEqualToString:@"sileo.deb"', picker)
        self.assertIn('isEqualToString:@"zebra.deb"', picker)
        self.assertIn('@"Unsupported or missing bundled RootHide package manager"', picker)
        self.assertIn('@"Select at least one package manager"', picker)
        self.assertIn("!S_ISREG(st.st_mode)", picker)
        self.assertIn("if (!packages) return selectionError;", install)
        self.assertIn('JBROOT_PATH("/usr/bin/dpkg")', install)
        self.assertIn('"-i"', install)
        self.assertIn("RH3WaitForBootstrapChild(pid, 120)", install)

    def test_bundled_manager_payloads_match_rooted_paths_and_bundle_ids(self):
        """Catch bad deb updates that hash or install fine but cannot register."""
        expected = {
            "roothide_sileo.deb": ("org.coolstar.sileo", "Sileo", "org.coolstar.SileoStore"),
            "roothide_zebra.deb": ("xyz.willy.zebra", "Zebra", "xyz.willy.Zebra"),
            "roothideapp.deb": ("com.roothide.manager", "RootHide", "com.roothide.manager"),
        }
        for filename, (package, app, bundle_id) in expected.items():
            with self.subTest(filename=filename):
                blob = (ROOT / "Application/Dopamine/Resources" / filename).read_bytes()
                pinned = re.search(r'@"' + re.escape(filename) + r'": @"([0-9a-f]{64})"', BOOTSTRAP)
                self.assertIsNotNone(pinned)
                self.assertEqual(hashlib.sha256(blob).hexdigest(), pinned.group(1))
                members = deb_members(blob)
                control = tar_entries(members, "control")
                values = {
                    key: value for key, value in
                    (line.split(": ", 1) for line in control["control"].decode().splitlines()
                     if ": " in line)
                }
                self.assertEqual(values["Package"], package)
                self.assertEqual(values["Architecture"], "iphoneos-arm64e")
                payload = tar_entries(members, "data")
                plist_path = "Applications/" + app + ".app/Info.plist"
                self.assertIn(plist_path, payload)
                info = plistlib.loads(payload[plist_path])
                self.assertEqual(info["CFBundleIdentifier"], bundle_id)
                self.assertEqual(info["CFBundleExecutable"], app)
                self.assertNotIn("var/jb/Applications/" + app + ".app/Info.plist", payload)

    def test_rejects_broken_or_duplicate_deb_members(self):
        with self.assertRaises(ValueError):
            deb_members(b"not a deb")
        blob = (ROOT / "Application/Dopamine/Resources/roothide_sileo.deb").read_bytes()
        with self.assertRaises(ValueError):
            deb_members(blob[:-1])
        with self.assertRaises(ValueError):
            deb_members(blob + blob[8:])

    def test_reactivation_preserves_packages_and_reregisters_existing_bundles(self):
        finalize = method(BOOTSTRAP, "- (NSError *)finalizeRootHideBootstrap\n{",
                          "- (NSError *)deleteRootHideBootstrap\n{")
        self.assertIn("if (!installed) {", finalize)
        installing = finalize.index("NSError *error = [self installPackageManagers]")
        manager = finalize.index('@"roothideapp.deb"')
        inventory = finalize.index("RH3RecordInstalledAppInventory(root)")
        commit = finalize.index('@"3" writeToFile:marker') if '@"3" writeToFile:marker' in finalize else finalize.index('writeToFile:marker atomically:YES')
        self.assertLess(installing, manager)
        self.assertLess(manager, inventory)
        self.assertLess(inventory, commit)
        # The old root's LaunchServices paths are stale after re-randomization.
        # The targeted registration helper is bounded and executes without
        # replacing packages or regenerating existing APT sources.
        self.assertNotIn('JBROOT_PATH(@"/usr/bin/uicache")', finalize)
        self.assertNotIn('JBROOT_PATH("/usr/bin/uicache")', finalize)
        self.assertIn('RH3RegisterPinnedJailbreakApps(root, installed)', finalize)
        refresh = method(ENVIRONMENT, "- (int)refreshJailbreakApps",
                         "// Read-only diagnosis for hardware")
        self.assertIn('repairRootHideAppLinks', refresh)
        self.assertIn('RH3CanonicalAppPath(registered.bundleURL.path)', refresh)
        self.assertIn('RH3CanonicalAppPath(path)', refresh)
        self.assertIn('arguments:@[@"-p", path]', refresh)
        self.assertIn('timeout:30', refresh)
        self.assertNotIn('arguments:@[@"-a"]', refresh.split('    [self runAsRoot:', 1)[0])


if __name__ == "__main__":
    unittest.main()
