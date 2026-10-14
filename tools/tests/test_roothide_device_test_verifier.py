"""Fixture-driven inspection of the GUI-only RootHide 3 IPA."""

import io
import plistlib
from pathlib import Path
import tempfile
import unittest
import zipfile

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


if __name__ == "__main__":
    unittest.main()
