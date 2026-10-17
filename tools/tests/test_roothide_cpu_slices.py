"""An ABI package label cannot replace checking actual Mach-O slices."""
import io
import tarfile
import unittest

from tools.verify_roothide_cpu_slices import check_payload, deb_payload
from tools.tests.test_verify_roothide_build import thin_macho


def payload(binary):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        member = tarfile.TarInfo("usr/bin/test")
        member.size = len(binary)
        archive.addfile(member, io.BytesIO(binary))
    return output.getvalue()


class CPUSliceTests(unittest.TestCase):
    def test_arm64_payload_is_accepted(self):
        self.assertEqual(check_payload(payload(thin_macho()), "test"), 1)

    def test_arm64e_only_payload_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing the required arm64"):
            check_payload(payload(thin_macho(subtype=2)), "test")

    def test_truncated_macho_does_not_count_as_valid_cpu_support(self):
        with self.assertRaisesRegex(ValueError, "invalid 64-bit Mach-O header"):
            check_payload(payload(b"\xcf\xfa\xed\xfe"), "test")

    def test_empty_payload_does_not_pass(self):
        with self.assertRaisesRegex(ValueError, "no Mach-O"):
            check_payload(payload(b"not an executable"), "test")

    def test_missing_and_truncated_debian_payloads_fail(self):
        for data in (b"!<arch>\n", b"!<arch>\nbad", b"not a deb"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                deb_payload(data)
