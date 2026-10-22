"""Host signing-envelope fixtures; not a CMS or Apple provisioning test."""

import plistlib
import struct
import unittest

from tools.verify_roothide_app_signature import inspect_main_signature


def signed_fixture(entitlements: dict, *, include_code_directory=True,
                   include_entitlements=True, broken_offset=False) -> bytes:
    members = []
    if include_code_directory:
        members.append((0, struct.pack(">II", 0xFADE0C02, 12) + b"DATA"))
    if include_entitlements:
        data = plistlib.dumps(entitlements)
        members.append((5, struct.pack(">II", 0xFADE7171, len(data) + 8) + data))
    cursor = 12 + 8 * len(members)
    children = bytearray()
    index = bytearray()
    for slot, item in members:
        index.extend(struct.pack(">II", slot, cursor + (0xFFFF if broken_offset else 0)))
        children.extend(item)
        cursor += len(item)
    signature = struct.pack(">III", 0xFADE0CC0, cursor, len(members)) + index + children
    # cffaedfe is a standard little-endian Mach-O64 magic.
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 16, 0, 0)
    command = struct.pack("<IIII", 0x1D, 16, len(header) + 16, len(signature))
    return header + command + signature


class AppSignature(unittest.TestCase):
    def test_valid_embedded_signature_matches_entitlements(self):
        expected = {"platform-application": True, "com.apple.security.network.client": True}
        errors, details = inspect_main_signature(signed_fixture(expected), expected)
        self.assertFalse(errors, errors)
        self.assertTrue(details["code_directory_present"])
        self.assertTrue(details["entitlements_match"])
        self.assertEqual(details["signature_slots"], [0, 5])

    def test_refuses_missing_code_directory_and_missing_entitlements(self):
        expected = {"platform-application": True}
        for kwargs in ({"include_code_directory": False}, {"include_entitlements": False}):
            errors, _ = inspect_main_signature(signed_fixture(expected, **kwargs), expected)
            self.assertTrue(errors)

    def test_refuses_mismatched_entitlements_and_out_of_range_slot(self):
        expected = {"platform-application": True}
        errors, _ = inspect_main_signature(signed_fixture({"platform-application": False}), expected)
        self.assertIn("Signed entitlements differ from pinned application policy", errors)
        errors, _ = inspect_main_signature(signed_fixture(expected, broken_offset=True), expected)
        self.assertIn("Duplicate or invalid signature slot", errors)

    def test_refuses_mutated_or_missing_load_commands(self):
        expected = {"platform-application": True}
        self.assertTrue(inspect_main_signature(b"not a macho", expected)[0])
        image = bytearray(signed_fixture(expected))
        struct.pack_into("<I", image, 32, 0xDEADBEEF)
        self.assertTrue(inspect_main_signature(bytes(image), expected)[0])


if __name__ == "__main__":
    unittest.main()
