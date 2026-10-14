"""Hermetic tests for the post-build IPA inspection (not device tests)."""

import hashlib
import io
import plistlib
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools import verify_roothide_build as verifier


# Explicit fixture contents, independent of the verifier's required-file list:
# a mistakenly removed validation entry must still fail the missing-file tests.
NEW_REQUIRED_BASEBIN_FILES = (
    "bootstrapper",
    "dopamine",
    "jailbreakd",
    "dyldhook_merge.arm64e.iOS15.dylib",
    "dyldhook_merge.arm64.iOS15.dylib",
    "dyldhook_merge.arm64e.iOS16-17.dylib",
    "dyldhook_merge.arm64.iOS16-17.dylib",
    "dyldhook_merge.arm64e.iOS18+.dylib",
    "dyldhook_merge.arm64.iOS18+.dylib",
)

BASEBIN_FIXTURE_FILES = (
    "libjailbreak.dylib",
    "launchdhook.dylib",
    "systemhook.dylib",
    "roothidehooks.dylib",
    "rootlesshooks.dylib",
    "hookd",
    "jbctl",
    *NEW_REQUIRED_BASEBIN_FILES,
    "basebin.tc",
)


def thin_macho(*, subtype=0, filetype=2, extra_commands=b""):
    """A minimal structurally valid arm64 Mach-O with a __TEXT segment."""
    segment_size = 72
    header_size = 32
    payload = b"\x00" * 32
    total = header_size + segment_size + len(extra_commands) + len(payload)
    commands = 1
    offset = 0
    while offset < len(extra_commands):
        size = struct.unpack_from("<I", extra_commands, offset + 4)[0]
        assert size >= 8 and offset + size <= len(extra_commands)
        offset += size
        commands += 1
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C,
                         subtype if subtype < 0x80000000 else subtype - 0x100000000,
                         filetype, commands, segment_size + len(extra_commands), 0, 0)
    segment = struct.pack("<II16sQQQQiiII", 0x19, segment_size,
                          b"__TEXT", 0, total, 0, total, 7, 5, 0, 0)
    return header + segment + extra_commands + payload


def fat_macho(*, fat64=False, endianness=">"):
    """Two aligned ARM64 and ARM64E slices with matching fat architecture records."""
    slices = [thin_macho(), thin_macho(subtype=0x80000002, filetype=6)]
    entry_size = 32 if fat64 else 20
    table = bytearray(struct.pack(endianness + "II", 0xCAFEBABF if fat64 else 0xCAFEBABE, 2))
    output = bytearray(b"\x00" * (8 + 2 * entry_size))
    for i, content in enumerate(slices):
        offset = (len(output) + 15) & ~15
        output.extend(b"\x00" * (offset - len(output)))
        output.extend(content)
        subtype = 0 if i == 0 else -2147483646  # CPU_SUBTYPE_ARM64E with capabilities
        if fat64:
            table.extend(struct.pack(endianness + "iiQQII", 0x0100000C, subtype,
                                     offset, len(content), 4, 0))
        else:
            table.extend(struct.pack(endianness + "iiIII", 0x0100000C, subtype,
                                     offset, len(content), 4))
    output[:len(table)] = table
    return bytes(output)


def sample_basebin(missing=None, corrupt=None, wrong_arch=None):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name in BASEBIN_FIXTURE_FILES:
            if name == missing:
                continue
            if name == "basebin.tc":
                payload = b"trustcache-fixture"
            elif name == corrupt:
                payload = b"invalid-Mach-O" + b"x" * 64
            else:
                subtype = 2 if ".arm64e." in name else 0
                if name == wrong_arch:
                    subtype = 0 if subtype == 2 else 2
                payload = thin_macho(subtype=subtype, filetype=6 if name.endswith(".dylib") else 2)
            header = tarfile.TarInfo("basebin/" + name)
            header.size = len(payload)
            archive.addfile(header, io.BytesIO(payload))
    return result.getvalue()


def sample_ipa(path: Path, *, missing=None, corrupt=None, missing_basebin=None,
               corrupt_basebin=None, corrupt_executable=False):
    payload = b"dummy-test-resource"
    expected = hashlib.sha256(payload).hexdigest()
    with patch.dict(verifier.PINNED_RESOURCES,
                    {name: expected for name in verifier.PINNED_RESOURCES}):
        with zipfile.ZipFile(path, "w") as archive:
            prefix = "Payload/Dopamine.app/"
            archive.writestr(prefix + "Info.plist", plistlib.dumps({
                "CFBundleExecutable": "Dopamine",
                "CFBundleIdentifier": "com.opa334.Dopamine",
            }))
            archive.writestr(prefix + "Dopamine", (b"\xcf\xfa\xed\xfe" + b"\x00" * 128)
                             if corrupt_executable else thin_macho())
            archive.writestr(prefix + "basebin.tar", sample_basebin(missing_basebin, corrupt_basebin))
            archive.writestr(prefix + "basebin.tc", b"test-trustcache")
            for name in verifier.PINNED_RESOURCES:
                if name != missing:
                    archive.writestr(prefix + name,
                                     payload if name != corrupt else b"wrong")
        return verifier.check_ipa(path)[0]


class BuildArtifactVerificationTests(unittest.TestCase):
    def test_complete_quarantined_build_has_no_missing_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(sample_ipa(Path(directory) / "Dopamine.ipa"), [])

    def test_missing_roothide_manager_is_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            errors = sample_ipa(Path(directory) / "Dopamine.ipa", missing="roothideapp.deb")
            self.assertTrue(any("roothideapp.deb" in message for message in errors))

    def test_resource_sha_mismatch_is_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            errors = sample_ipa(Path(directory) / "Dopamine.ipa", corrupt="roothide_sileo.deb")
            self.assertTrue(any("hash mismatch" in message for message in errors))

    def test_missing_roothidehooks_dylib_is_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            errors = sample_ipa(Path(directory) / "Dopamine.ipa", missing_basebin="roothidehooks.dylib")
            self.assertTrue(any("roothidehooks.dylib" in message for message in errors))

    def test_missing_bootstrapper_daemons_or_dyldhook_variants_are_blocking(self):
        for name in NEW_REQUIRED_BASEBIN_FILES:
            with self.subTest(missing=name), tempfile.TemporaryDirectory() as directory:
                errors = sample_ipa(Path(directory) / "Dopamine.ipa", missing_basebin=name)
                self.assertIn(f"basebin.tar missing {name}", errors)

    def test_invalid_macho_in_bootstrapper_daemons_or_dyldhook_is_blocking(self):
        for name in NEW_REQUIRED_BASEBIN_FILES:
            with self.subTest(corrupt=name), tempfile.TemporaryDirectory() as directory:
                errors = sample_ipa(Path(directory) / "Dopamine.ipa", corrupt_basebin=name)
                self.assertIn(f"basebin.tar contains invalid Mach-O: {name}", errors)

    def test_dyldhook_named_architecture_must_exist_in_binary(self):
        for name in ("dyldhook_merge.arm64.iOS15.dylib", "dyldhook_merge.arm64e.iOS15.dylib"):
            with self.subTest(name=name):
                errors = verifier.check_basebin_bytes(sample_basebin(wrong_arch=name))
                self.assertIn(f"basebin.tar contains invalid Mach-O: {name}", errors)

    def test_malformed_tar_is_blocking(self):
        self.assertTrue(any("Invalid basebin.tar" in message
                            for message in verifier.check_basebin_bytes(b"wrong")))

    def test_non_macho_image_is_rejected(self):
        self.assertFalse(verifier.is_macho(b"HELLO" + b"0" * 60))
        self.assertFalse(verifier.is_macho(bytes.fromhex("cafebabe") + b"0" * 64))
        self.assertFalse(verifier.is_macho(bytes.fromhex("cffaedfe") + b"0" * 128))

    def test_structural_arm64_thin_and_fat_images_are_accepted(self):
        for content in (thin_macho(), thin_macho(subtype=1), thin_macho(subtype=2),
                        thin_macho(subtype=0x80000002, filetype=6),
                        fat_macho(), fat_macho(fat64=True),
                        fat_macho(endianness="<"), fat_macho(fat64=True, endianness="<")):
            with self.subTest(magic=content[:4].hex(), length=len(content)):
                self.assertIsNone(verifier.validate_macho(content))

    def test_thin_rejects_corrupt_header_and_load_commands(self):
        cases = {
            "truncated header": (0, b"\x00", None),
            "wrong CPU": (4, struct.pack("<i", 0x01000007), "CPU"),
            "wrong subtype": (8, struct.pack("<i", 15), "CPU"),
            "empty load commands": (16, struct.pack("<I", 0), "load-command"),
            "load commands too long": (20, struct.pack("<I", 10000), "load commands"),
            "zero load command size": (36, struct.pack("<I", 0), "load-command"),
            "unaligned load command": (36, struct.pack("<I", 73), "load-command"),
            "segment outside file": (72, struct.pack("<Q", 10000), "segment"),
            "oversized section table": (96, struct.pack("<I", 1), "sections"),
        }
        for label, (offset, replacement, expected) in cases.items():
            with self.subTest(label=label):
                if label == "truncated header":
                    corrupt = thin_macho()[:16]
                else:
                    corrupt = bytearray(thin_macho())
                    corrupt[offset:offset + len(replacement)] = replacement
                result = verifier.validate_macho(corrupt)
                self.assertIsNotNone(result)
                if expected:
                    self.assertIn(expected.lower(), result.lower())

    def test_thin_rejects_corrupt_linkedit_and_entry_offsets(self):
        extra_commands = (
            struct.pack("<IIIIII", 0x2, 24, 0, 0, 0, 0) +
            struct.pack("<IIII", 0x1D, 16, 0, 0) +
            struct.pack("<IIQQ", 0x80000028, 24, 0, 0)
        )
        good = thin_macho(extra_commands=extra_commands)
        self.assertIsNone(verifier.validate_macho(good))
        # Header 32 + segment 72 -> LC_SYMTAB; LC_CODE_SIGNATURE follows at 128.
        for label, offset, value in (
            ("symbol table", 112, 0xFFFFFFF0),
            ("code signature", 136, 0xFFFFFFF0),
            ("entry point", 152, 0xFFFFFFF0),
        ):
            with self.subTest(label=label):
                corrupt = bytearray(good)
                struct.pack_into("<I", corrupt, offset, value)
                # Make sure the indicated data range is nonempty.
                if label == "symbol table":
                    struct.pack_into("<I", corrupt, 116, 1)
                elif label == "code signature":
                    struct.pack_into("<I", corrupt, 140, 8)
                self.assertIsNotNone(verifier.validate_macho(corrupt))

    def test_fat_rejects_invalid_slices_and_architecture_records(self):
        original = fat_macho()
        for label, offset, replacement in (
            ("outside file", 16, struct.pack(">I", 0xFFFFFFF0)),
            ("wrong CPU", 8, struct.pack(">i", 0x01000007)),
            ("wrong subtype", 12, struct.pack(">i", 2)),
            ("bad alignment", 24, struct.pack(">I", 31)),
            ("overlap", 36, struct.pack(">I", 48)),
        ):
            with self.subTest(label=label):
                corrupt = bytearray(original)
                corrupt[offset:offset + len(replacement)] = replacement
                if label == "overlap":
                    # Match the first slice's subtype so the overlap check
                    # itself is reached rather than the CPU mismatch check.
                    struct.pack_into(">i", corrupt, 32, 0)
                result = verifier.validate_macho(corrupt)
                self.assertIsNotNone(result)
                if label == "overlap":
                    self.assertIn("overlapping", result)
        self.assertIsNotNone(verifier.validate_macho(original[:-1]))

    def test_packaged_image_with_fake_magic_is_rejected(self):
        self.assertTrue(verifier.check_basebin_bytes(sample_basebin(corrupt="jailbreakd")))
        with tempfile.TemporaryDirectory() as directory:
            errors = sample_ipa(Path(directory) / "Dopamine.ipa", corrupt_executable=True)
            self.assertIn("The app executable is not a valid Mach-O image", errors)

    def test_dynamic_symbol_encryption_and_hint_offsets_are_checked(self):
        extra_commands = (
            struct.pack("<II", 0xB, 80) + b"\x00" * 72 +
            struct.pack("<IIIIII", 0x2C, 24, 0, 0, 0, 0) +
            struct.pack("<IIII", 0x16, 16, 0, 0)
        )
        good = thin_macho(extra_commands=extra_commands)
        self.assertIsNone(verifier.validate_macho(good))
        # First command starts after header (32) and __TEXT segment (72).
        for label, offset, size_offset in (
            ("LC_DYSYMTAB", 136, 140),
            ("LC_ENCRYPTION_INFO_64", 192, 196),
            ("LC_TWOLEVEL_HINTS", 216, 220),
        ):
            with self.subTest(label=label):
                corrupt = bytearray(good)
                struct.pack_into("<I", corrupt, offset, len(good) + 1)
                struct.pack_into("<I", corrupt, size_offset, 1)
                self.assertIn(label, verifier.validate_macho(corrupt))


if __name__ == "__main__":
    unittest.main()
