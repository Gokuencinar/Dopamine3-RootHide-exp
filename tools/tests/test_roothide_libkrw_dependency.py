"""Guard the RootHide-specific libkrw virtual provider against regressions.

The actual plugin comes from Dopamine and is copied only into the verified
hidden root. The official RootHide *metadata-only* package provides the
missing dpkg/APT relationship without exposing a /var/jb bootstrap.
"""
import hashlib
import io
from pathlib import Path
import tarfile
import unittest

from tools.verify_roothide_cpu_slices import check_empty_provider_payload, deb_payload

ROOT = Path(__file__).resolve().parents[2]
NAME = "roothide_libkrw0_dummy.deb"
SHA = "2e0054419a379ba3ca8d42f5769cbdcd1b85e5e753a73cf1204039472e0388b4"


def deb_members(data):
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("invalid ar")
    cursor = 8
    while cursor < len(data):
        header = data[cursor:cursor + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            raise ValueError("invalid member header")
        name = header[:16].strip().rstrip(b"/").decode("ascii")
        size = int(header[48:58])
        cursor += 60
        if cursor + size > len(data):
            raise ValueError("truncated member")
        yield name, data[cursor:cursor + size]
        cursor += size + size % 2


class LibkrwProvider(unittest.TestCase):
    def test_official_roothide_dummy_is_pinned_arm64e_and_metadata_only(self):
        data = (ROOT / "Application/Dopamine/Resources" / NAME).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), SHA)
        archives = {name: payload for name, payload in deb_members(data)}
        control_archive = next(name for name in archives if name.startswith("control.tar."))
        data_archive = next(name for name in archives if name.startswith("data.tar."))
        with tarfile.open(fileobj=io.BytesIO(archives[control_archive]), mode="r:*") as tar:
            metadata = tar.extractfile("./control").read().decode("utf8")
        self.assertIn("Package: libkrw0-dummy\n", metadata)
        self.assertIn("Architecture: iphoneos-arm64e\n", metadata)
        self.assertIn("Provides: libkrw0-plugin\n", metadata)
        self.assertIn("Depends: libiosexec1", metadata)
        self.assertIn("libkrw0", metadata)
        with tarfile.open(fileobj=io.BytesIO(archives[data_archive]), mode="r:*") as tar:
            self.assertFalse([member for member in tar if member.isfile() or member.issym()])
        check_empty_provider_payload(deb_payload(data))

    def test_cpu_verifier_rejects_any_payload_added_to_virtual_provider(self):
        blob = io.BytesIO()
        with tarfile.open(fileobj=blob, mode="w") as archive:
            payload = b"untrusted"
            entry = tarfile.TarInfo("usr/lib/rogue.dylib")
            entry.size = len(payload)
            archive.addfile(entry, io.BytesIO(payload))
        with self.assertRaisesRegex(ValueError, "unexpected payload"):
            check_empty_provider_payload(blob.getvalue())

    def test_package_is_verified_and_bundled_in_hardware_beta(self):
        bootstrap = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text()
        verifier = (ROOT / "tools/verify_roothide_build.py").read_text()
        project = (ROOT / "Application/Dopamine.xcodeproj/project.pbxproj").read_text()
        self.assertIn(f'@"{NAME}": @"{SHA}"', bootstrap)
        self.assertIn(f'"{NAME}": "{SHA}"', verifier)
        self.assertIn(f'/* {NAME} in Resources */', project)
        self.assertIn(f'/* {NAME} */', project)
        self.assertIn("rootHideLibkrwProviderPackageWithError:", bootstrap)
        install = bootstrap.split("- (NSError *)finalizeRootHideBootstrap\n{", 1)[1].split("- (NSError *)deleteRootHideBootstrap\n{", 1)[0]
        fresh = install.split("if (!installed) {", 1)[1]  # branch follows dependency setup
        self.assertLess(fresh.index("rootHideLibkrwProviderPackageWithError:"), fresh.index("installPackageManagers]"))
        self.assertIn('"-i", provider.fileSystemRepresentation', fresh)
        self.assertIn("if (providerResult)", fresh)
        self.assertNotIn('"/var/jb"', fresh.split("installPackageManagers]", 1)[0])

    def test_existing_root_repair_is_explicit_and_checks_real_binary(self):
        env = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text()
        repairs = env.split("- (NSError *)repairRootHideLibkrwProvider", 1)[1].split("- (NSError*)updateBootLogo", 1)[0]
        self.assertIn("rootHideExistingRootWithError:", repairs)
        self.assertIn("jbclient_get_jbroot()", repairs)
        self.assertIn('"usr/lib/libkrw/libkrw-dopamine.dylib"', repairs)
        self.assertIn("lstat(library.fileSystemRepresentation", repairs)
        self.assertLess(repairs.index("lstat(library.fileSystemRepresentation"), repairs.index("spawnJbctlAsRootWithArgs:"))
        self.assertIn('@[@"internal", @"install_pkg", provider]', repairs)
        settings = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m").read_text()
        self.assertIn('@"Reparar dependencia libkrw (Sileo)"', settings)
        self.assertIn("gRootHideProviderRepairInFlight", settings)
        self.assertIn("repairRootHideLibkrwPressed", settings)
        self.assertIn("operation outcome unknown; duplicate repair blocked", settings)


if __name__ == "__main__":
    unittest.main()
