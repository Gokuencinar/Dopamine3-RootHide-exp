#!/usr/bin/env python3
"""Inspect a compiled RootHide/Dopamine 3 IPA, not certify device functionality.

This check deliberately accepts a build with the RootHide enable flag *off*:
the result is a quarantined compilation artifact, never an install-ready
RootHide release. Runtime behavior needs physical-device validation.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import plistlib
import struct
import sys
import tarfile
import zipfile

try:
    from .roothide_port_audit import ROOT
except ImportError:
    from roothide_port_audit import ROOT  # direct command-line invocation


PINNED_RESOURCES = {
    "roothide_bootstrap_1800.tar.zst": "3350ed91d77163e0cd73f0f90185b5c9b87d9d294133e25ced3a29329e90370e",
    "roothide_bootstrap_1900.tar.zst": "420f72d1a62c9f884733cdefc596728469482a48858ec7ceca4d3ab2d3cba56c",
    "roothideapp.deb": "b8f075e1844709845962900b22fe71136a66369a2c35bb1201087f2fd9476b7d",
    "roothide_sileo.deb": "e85ab12f8d98da9a5350293647266b898282b0d766df2397526ab253d84eede3",
    "roothide_zebra.deb": "ca82c18256e19ff78af3e53308d53f047a2d429cb7e025c892377abe4d2e7825",
}

# BaseBin/dyldhook/Makefile builds all six variants and BaseBin/Makefile
# copies dyldhook/*.dylib into .build before creating basebin.tar. There is
# no single "dyldhook.dylib" in the archive.
REQUIRED_DYLDHOOK = (
    "dyldhook_merge.arm64e.iOS15.dylib",
    "dyldhook_merge.arm64.iOS15.dylib",
    "dyldhook_merge.arm64e.iOS16-17.dylib",
    "dyldhook_merge.arm64.iOS16-17.dylib",
    "dyldhook_merge.arm64e.iOS18+.dylib",
    "dyldhook_merge.arm64.iOS18+.dylib",
)

REQUIRED_BASEBIN = (
    "libjailbreak.dylib",
    "launchdhook.dylib",
    "systemhook.dylib",
    "roothidehooks.dylib",
    "rootlesshooks.dylib",
    "hookd",
    "jbctl",
    "bootstrapper",
    "dopamine",
    "jailbreakd",
    *REQUIRED_DYLDHOOK,
    "basebin.tc",
)

ARM64_CPU_TYPE = 0x0100000C
ARM64_SUBTYPES = {0, 1, 2}  # ARM64_ALL, ARM64_V8, ARM64E
THIN_MAGICS = {
    bytes.fromhex("cffaedfe"): "<",  # MH_CIGAM_64 (common iOS format)
    bytes.fromhex("feedfacf"): ">",  # MH_MAGIC_64
}
FAT_MAGICS = {
    bytes.fromhex("cafebabe"): (">", False),  # FAT_MAGIC
    bytes.fromhex("bebafeca"): ("<", False),  # FAT_CIGAM
    bytes.fromhex("cafebabf"): (">", True),   # FAT_MAGIC_64
    bytes.fromhex("bfbafeca"): ("<", True),   # FAT_CIGAM_64
}


def _in_bounds(offset: int, size: int, length: int) -> bool:
    return offset >= 0 and size >= 0 and offset <= length and size <= length - offset


def _validate_thin_macho(content: bytes | memoryview) -> tuple[int, int]:
    """Check the on-disk ARM64 Mach-O layout, not its signature or behavior."""
    if len(content) < 32 or bytes(content[:4]) not in THIN_MAGICS:
        raise ValueError("invalid 64-bit Mach-O header")
    endian = THIN_MAGICS[bytes(content[:4])]
    _, cpu, subtype, filetype, ncmds, sizeofcmds, _, _ = struct.unpack_from(
        endian + "IiiIIIII", content
    )
    if cpu != ARM64_CPU_TYPE or (subtype & 0x00FFFFFF) not in ARM64_SUBTYPES:
        raise ValueError("missing supported arm64/arm64e CPU type")
    if filetype == 0 or not ncmds or not sizeofcmds or ncmds > sizeofcmds // 8:
        raise ValueError("invalid Mach-O file type or load-command count")
    command_end = 32 + sizeofcmds
    if command_end > len(content):
        raise ValueError("load commands extend beyond the Mach-O slice")

    cursor = 32
    has_segment = False
    for _ in range(ncmds):
        if cursor + 8 > command_end:
            raise ValueError("truncated Mach-O load command")
        cmd, cmdsize = struct.unpack_from(endian + "II", content, cursor)
        if cmdsize < 8 or cmdsize % 8 or cmdsize > command_end - cursor:
            raise ValueError("invalid Mach-O load-command size")

        if cmd == 0x19:  # LC_SEGMENT_64
            if cmdsize < 72:
                raise ValueError("truncated LC_SEGMENT_64")
            fileoff, filesize = struct.unpack_from(endian + "QQ", content, cursor + 40)
            nsects = struct.unpack_from(endian + "I", content, cursor + 64)[0]
            if nsects > (cmdsize - 72) // 80:
                raise ValueError("LC_SEGMENT_64 sections exceed command size")
            if not _in_bounds(fileoff, filesize, len(content)):
                raise ValueError("LC_SEGMENT_64 file range exceeds slice")
            for section in range(nsects):
                section_start = cursor + 72 + section * 80
                section_size = struct.unpack_from(endian + "Q", content, section_start + 40)[0]
                section_offset = struct.unpack_from(endian + "I", content, section_start + 48)[0]
                section_flags = struct.unpack_from(endian + "I", content, section_start + 64)[0]
                # Zerofill sections occupy VM space but no bytes in the file.
                if (section_flags & 0xFF) not in {1, 0xC, 0x12} and section_size:
                    if not _in_bounds(section_offset, section_size, len(content)):
                        raise ValueError("LC_SEGMENT_64 section data exceeds slice")
            has_segment = True
        elif cmd == 0x2:  # LC_SYMTAB: nlist_64 records and the string table
            if cmdsize < 24:
                raise ValueError("truncated LC_SYMTAB")
            symoff, nsyms, stroff, strsize = struct.unpack_from(
                endian + "IIII", content, cursor + 8
            )
            if not (_in_bounds(symoff, nsyms * 16, len(content)) and
                    _in_bounds(stroff, strsize, len(content))):
                raise ValueError("LC_SYMTAB data exceeds slice")
        elif cmd == 0xB:  # LC_DYSYMTAB: six file-offset/count table pairs
            if cmdsize < 80:
                raise ValueError("truncated LC_DYSYMTAB")
            for pair, record_size in enumerate((8, 56, 4, 4, 8, 8)):
                offset, count = struct.unpack_from(endian + "II", content, cursor + 32 + pair * 8)
                if not _in_bounds(offset, count * record_size, len(content)):
                    raise ValueError("LC_DYSYMTAB data exceeds slice")
        elif cmd in {0x22, 0x80000022}:  # LC_DYLD_INFO / LC_DYLD_INFO_ONLY
            if cmdsize < 48:
                raise ValueError("truncated LC_DYLD_INFO")
            for pair in range(5):
                offset, size = struct.unpack_from(endian + "II", content, cursor + 8 + pair * 8)
                if not _in_bounds(offset, size, len(content)):
                    raise ValueError("LC_DYLD_INFO data exceeds slice")
        elif cmd in {0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x80000033, 0x80000034}:
            # LC_CODE_SIGNATURE and other linkedit_data_command variants.
            if cmdsize < 16:
                raise ValueError("truncated linkedit data command")
            offset, size = struct.unpack_from(endian + "II", content, cursor + 8)
            if not _in_bounds(offset, size, len(content)):
                raise ValueError("linkedit data exceeds slice")
        elif cmd == 0x80000028:  # LC_MAIN
            if cmdsize < 24:
                raise ValueError("truncated LC_MAIN")
            entryoff = struct.unpack_from(endian + "Q", content, cursor + 8)[0]
            if entryoff >= len(content):
                raise ValueError("LC_MAIN entry offset exceeds slice")
        elif cmd == 0x2C:  # LC_ENCRYPTION_INFO_64
            if cmdsize < 24:
                raise ValueError("truncated LC_ENCRYPTION_INFO_64")
            offset, size = struct.unpack_from(endian + "II", content, cursor + 8)
            if not _in_bounds(offset, size, len(content)):
                raise ValueError("LC_ENCRYPTION_INFO_64 range exceeds slice")
        elif cmd == 0x16:  # LC_TWOLEVEL_HINTS (4 bytes per hint)
            if cmdsize < 16:
                raise ValueError("truncated LC_TWOLEVEL_HINTS")
            offset, count = struct.unpack_from(endian + "II", content, cursor + 8)
            if not _in_bounds(offset, count * 4, len(content)):
                raise ValueError("LC_TWOLEVEL_HINTS data exceeds slice")
        elif cmd == 0x31:  # LC_NOTE
            if cmdsize < 40:
                raise ValueError("truncated LC_NOTE")
            offset, size = struct.unpack_from(endian + "QQ", content, cursor + 24)
            if not _in_bounds(offset, size, len(content)):
                raise ValueError("LC_NOTE data exceeds slice")
        cursor += cmdsize

    if cursor != command_end or not has_segment:
        raise ValueError("invalid load-command table or missing LC_SEGMENT_64")
    return cpu, subtype & 0x00FFFFFF


def validate_macho(content: bytes, *, required_arch: str | None = None) -> str | None:
    """Return a structural error, or None for a well-formed ARM64 Mach-O.

    This is deliberately not code-signature verification, entitlement checking,
    device compatibility testing, or a guarantee of executable machine code.
    """
    try:
        if len(content) < 4:
            raise ValueError("truncated Mach-O magic")
        magic = bytes(content[:4])
        subtypes: set[int] = set()
        if magic in THIN_MAGICS:
            subtypes.add(_validate_thin_macho(content)[1])
        elif magic in FAT_MAGICS:
            if len(content) < 8:
                raise ValueError("truncated fat Mach-O header")
            endian, fat64 = FAT_MAGICS[magic]
            count = struct.unpack_from(endian + "I", content, 4)[0]
            entry_size = 32 if fat64 else 20
            table_end = 8 + count * entry_size
            if not count or table_end > len(content):
                raise ValueError("invalid fat Mach-O architecture table")
            ranges: list[tuple[int, int]] = []
            for i in range(count):
                entry = 8 + i * entry_size
                cpu, subtype = struct.unpack_from(endian + "ii", content, entry)
                if fat64:
                    offset, size, align = struct.unpack_from(endian + "QQI", content, entry + 8)
                else:
                    offset, size, align = struct.unpack_from(endian + "III", content, entry + 8)
                if (align > 31 or offset % (1 << align) or offset < table_end or
                        not _in_bounds(offset, size, len(content)) or size < 32):
                    raise ValueError("invalid fat Mach-O slice offset, size or alignment")
                inner_cpu, inner_subtype = _validate_thin_macho(memoryview(content)[offset:offset + size])
                if (cpu, subtype & 0x00FFFFFF) != (inner_cpu, inner_subtype):
                    raise ValueError("fat Mach-O architecture disagrees with its slice")
                subtypes.add(inner_subtype)
                ranges.append((offset, offset + size))
            ranges.sort()
            if any(end > following_start for (_, end), (following_start, _) in zip(ranges, ranges[1:])):
                raise ValueError("overlapping fat Mach-O slices")
        else:
            raise ValueError("unrecognized Mach-O magic")
        if (required_arch == "arm64e" and 2 not in subtypes) or (
                required_arch == "arm64" and not subtypes.intersection({0, 1})):
            raise ValueError(f"Mach-O is missing the required {required_arch} architecture")
    except (ValueError, struct.error) as exc:
        return str(exc)
    return None


def is_macho(content: bytes) -> bool:
    return validate_macho(content) is None


def check_ipa(path: Path) -> tuple[list[str], dict]:
    errors: list[str] = []
    details: dict = {"ipa": str(path), "bytes": path.stat().st_size if path.exists() else 0}
    if not path.is_file():
        return ["IPA file does not exist"], details
    try:
        with zipfile.ZipFile(path) as ipa:
            bad = ipa.testzip()
            if bad:
                errors.append(f"IPA ZIP checksum failure: {bad}")
            names = set(ipa.namelist())
            prefix = "Payload/Dopamine.app/"
            info_path = prefix + "Info.plist"
            if info_path not in names:
                errors.append("IPA is missing the application Info.plist")
            else:
                info = plistlib.loads(ipa.read(info_path))
                executable = info.get("CFBundleExecutable")
                identifier = info.get("CFBundleIdentifier")
                details["bundle_id"] = identifier
                details["executable"] = executable
                if not isinstance(executable, str) or prefix + executable not in names:
                    errors.append("The declared app executable is absent")
                elif not is_macho(ipa.read(prefix + executable)):
                    errors.append("The app executable is not a valid Mach-O image")
            for filename, expected in PINNED_RESOURCES.items():
                resource = prefix + filename
                if resource not in names:
                    errors.append(f"Missing packaged RootHide resource: {filename}")
                elif hashlib.sha256(ipa.read(resource)).hexdigest() != expected:
                    errors.append(f"Resource hash mismatch: {filename}")
            basebin_resource = prefix + "basebin.tar"
            if basebin_resource not in names:
                errors.append("The app does not bundle basebin.tar")
            else:
                errors.extend(check_basebin_bytes(ipa.read(basebin_resource)))
            if prefix + "basebin.tc" not in names:
                errors.append("The app does not bundle basebin.tc")
    except (OSError, zipfile.BadZipFile, plistlib.InvalidFileException, ValueError) as exc:
        errors.append(f"Unable to inspect IPA: {exc}")
    return errors, details


def check_basebin_bytes(content: bytes) -> list[str]:
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as archive:
            files = {member.name.lstrip("./"): member for member in archive.getmembers() if member.isfile()}
            errors = []
            for name in REQUIRED_BASEBIN:
                key = f"basebin/{name}"
                member = files.get(key)
                if member is None:
                    errors.append(f"basebin.tar missing {name}")
                elif name != "basebin.tc":
                    extracted = archive.extractfile(member)
                    required_arch = None
                    if name.startswith("dyldhook_merge.arm64e."):
                        required_arch = "arm64e"
                    elif name.startswith("dyldhook_merge.arm64."):
                        required_arch = "arm64"
                    if not extracted or validate_macho(extracted.read(), required_arch=required_arch):
                        errors.append(f"basebin.tar contains invalid Mach-O: {name}")
            return errors
    except (tarfile.TarError, OSError) as exc:
        return [f"Invalid basebin.tar: {exc}"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipa", type=Path, default=ROOT / "Application/Dopamine.ipa")
    parser.add_argument("--json", action="store_true")
    options = parser.parse_args()
    errors, details = check_ipa(options.ipa)
    source = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(encoding="utf-8")
    gate_disabled = "#define ROOTHIDE3_BOOTSTRAP_READY 0" in source
    if not gate_disabled:
        errors.append("The safety gate was changed; manual review is required")
    result = {
        "status": "PASS" if not errors else "FAIL",
        "classification": "COMPILE-ONLY / NOT INSTALLABLE AS ROOTHIDE",
        "roothide_activation_disabled": gate_disabled,
        "details": details,
        "errors": errors,
    }
    if options.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{result['status']}: {result['classification']}")
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
