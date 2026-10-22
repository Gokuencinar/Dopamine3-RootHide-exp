#!/usr/bin/env python3
"""Verify the main IPA Mach-O's embedded signing envelope and exact entitlements.

This is a structural/ad-hoc signing check, NOT cryptographic CMS verification,
Apple provisioning, or proof that iOS will accept the user's sideload signature.
"""

import argparse
import json
from pathlib import Path
import plistlib
import struct
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MAIN_PATH = "Payload/Dopamine.app/Dopamine"
ENTITLEMENTS = ROOT / "Application/Dopamine/Dopamine.entitlements"


def inspect_main_signature(image: bytes, expected: dict) -> tuple[list[str], dict]:
    errors = []
    details = {"code_directory_present": False, "entitlements_match": False}
    if len(image) < 32 or image[:4] not in (bytes.fromhex("cffaedfe"), bytes.fromhex("feedfacf")):
        return ["Main app is not a thin 64-bit Mach-O"], details
    endian = "<" if image[:4] == bytes.fromhex("cffaedfe") else ">"
    commands, command_bytes = struct.unpack_from(endian + "II", image, 16)
    if not commands or commands > command_bytes // 8 or 32 + command_bytes > len(image):
        return ["Malformed Mach-O command table"], details
    offsets = []
    cursor = 32
    for _ in range(commands):
        if cursor + 8 > 32 + command_bytes:
            return ["Truncated Mach-O command"], details
        command, length = struct.unpack_from(endian + "II", image, cursor)
        if length < 8 or length % 8 or cursor + length > 32 + command_bytes:
            return ["Invalid Mach-O command length"], details
        if command == 0x1D:
            if length < 16:
                return ["Truncated LC_CODE_SIGNATURE"], details
            offsets.append(struct.unpack_from(endian + "II", image, cursor + 8))
        cursor += length
    if cursor != 32 + command_bytes or len(offsets) != 1:
        return ["Expected exactly one LC_CODE_SIGNATURE"], details
    offset, size = offsets[0]
    if size < 12 or offset + size > len(image):
        return ["Invalid LC_CODE_SIGNATURE range"], details
    blob = memoryview(image)[offset:offset + size]
    magic, total, count = struct.unpack_from(">III", blob, 0)
    if magic != 0xFADE0CC0 or total > size or total < 12 or count > (total - 12) // 8:
        return ["Invalid embedded signing superblob"], details
    slots = {}
    for i in range(count):
        slot, start = struct.unpack_from(">II", blob, 12 + 8 * i)
        if slot in slots or start + 8 > total or start < 12 + 8 * count:
            errors.append("Duplicate or invalid signature slot")
            continue
        child_magic, child_size = struct.unpack_from(">II", blob, start)
        if child_size < 8 or start + child_size > total:
            errors.append("Out-of-range signature slot")
            continue
        slots[slot] = (child_magic, bytes(blob[start + 8:start + child_size]))
    details["signature_slots"] = sorted(slots)
    details["code_directory_present"] = slots.get(0, (None,))[0] == 0xFADE0C02
    if not details["code_directory_present"]:
        errors.append("Embedded signature lacks CodeDirectory")
    if slots.get(5, (None,))[0] != 0xFADE7171:
        errors.append("Embedded signature lacks XML entitlements")
    else:
        try:
            actual = plistlib.loads(slots[5][1])
            details["entitlements_match"] = actual == expected
        except (ValueError, plistlib.InvalidFileException):
            errors.append("Invalid signed entitlements plist")
        if not details["entitlements_match"]:
            errors.append("Signed entitlements differ from pinned application policy")
    return errors, details


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipa", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    with zipfile.ZipFile(args.ipa) as archive:
        image = archive.read(MAIN_PATH)
    with ENTITLEMENTS.open("rb") as stream:
        expected = plistlib.load(stream)
    errors, details = inspect_main_signature(image, expected)
    result = {"status": "PASS" if not errors else "FAIL", "details": details,
              "errors": errors, "apple_provisioning_verified": False,
              "cryptographic_signature_verified": False}
    print(json.dumps(result, indent=2) if args.json else result)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
