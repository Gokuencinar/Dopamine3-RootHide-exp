"""Fixture-driven inspection of the GUI-only RootHide 3 IPA."""

import io
import plistlib
from pathlib import Path
import tempfile
import unittest
import zipfile
import warnings

from tools.verify_roothide_device_test import inspect_ipa, EXPECTED_BINARY_MARKER
from tools.tests.test_verify_roothide_build import thin_macho


class DeviceTestVerifierTests(unittest.TestCase):
    def make_ipa(self, path: Path, bundle="com.gokuencinar.roothide3.diagnostic",
                 display="RootHide 3 Test", extra=None, executable=None):
        plist = plistlib.dumps({"CFBundleIdentifier": bundle, "CFBundleDisplayName": display,
                               "CFBundleExecutable": "Dopamine", "CFBundlePackageType": "APPL",
                               "MinimumOSVersion": "15.0"})
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("Payload/Dopamine.app/Info.plist", plist)
            archive.writestr("Payload/Dopamine.app/Dopamine",
                             executable if executable is not None else thin_macho() + EXPECTED_BINARY_MARKER)
            if extra is not None:
                archive.writestr("Payload/Dopamine.app/" + extra, b"payload")

    def test_valid_gui_only_archive(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "diagnostic.ipa"
            self.make_ipa(path)
            errors, details = inspect_ipa(path)
            self.assertEqual(errors, [])
            self.assertEqual(details["bundle_id"], "com.gokuencinar.roothide3.diagnostic")

    def test_rejects_stock_identity_payloads_and_invalid_binary(self):
        with tempfile.TemporaryDirectory() as root:
            for label, options in (
                ("stock-id", {"bundle": "com.opa334.Dopamine"}),
                ("wrong-name", {"display": "Dopamine"}),
                ("basebin", {"extra": "basebin.tar"}),
                ("nested-basebin", {"extra": "Resources/payload/basebin.tar"}),
                ("manager", {"extra": "roothideapp.deb"}),
                ("nested-manager", {"extra": "Resources/packages/roothideapp.deb"}),
                ("embedded-framework", {"extra": "Frameworks/Privileged.framework/Privileged"}),
                ("unexpected-resource", {"extra": "README.txt"}),
                ("bootstrap", {"extra": "bootstrap_1800.tar.zst"}),
                ("missing-marker", {"executable": thin_macho()}),
                ("bad-binary", {"executable": b"not a Mach-O"}),
            ):
                with self.subTest(label=label):
                    path = Path(root) / (label + ".ipa")
                    self.make_ipa(path, **options)
                    errors, _ = inspect_ipa(path)
                    self.assertTrue(errors, f"Expected rejection of {label}")

    def test_missing_file_and_truncated_zip(self):
        with tempfile.TemporaryDirectory() as root:
            missing = Path(root) / "absent.ipa"
            self.assertTrue(inspect_ipa(missing)[0])
            missing.write_bytes(b"invalid archive")
            self.assertTrue(inspect_ipa(missing)[0])

    def test_rejects_unexpected_top_level_entries_duplicate_and_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            for label, member in (
                ("extra-app", "Payload/Unexpected.app/extra.bin"),
                ("traversal", "Payload/Dopamine.app/../unexpected"),
                ("backslash", "Payload\\Unexpected.app\\extra.bin"),
                ("hidden", ".hidden"),
                ("unexpected-directory", "Payload/Other.app/"),
            ):
                with self.subTest(label=label):
                    path = Path(root) / f"{label}.ipa"
                    self.make_ipa(path)
                    with zipfile.ZipFile(path, "a") as archive:
                        archive.writestr(member, b"payload")
                    self.assertTrue(inspect_ipa(path)[0])
            path = Path(root) / "duplicate.ipa"
            self.make_ipa(path)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "a") as archive:
                    archive.writestr("Payload/Dopamine.app/Info.plist", b"duplicate")
            self.assertTrue(inspect_ipa(path)[0])
            path = Path(root) / "symlink.ipa"
            self.make_ipa(path)
            link = zipfile.ZipInfo("Payload/Dopamine.app/README")
            link.create_system = 3
            link.external_attr = (0o120777 << 16)
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr(link, "something")
            self.assertTrue(inspect_ipa(path)[0])


if __name__ == "__main__":
    unittest.main()
