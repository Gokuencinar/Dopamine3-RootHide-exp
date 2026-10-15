#!/usr/bin/env python3
"""Inspect the complete, GUARDED RootHide 3/Dopamine IPA; not a jailbreak certificate.

Checks that the existing BaseBin/RootHide payload verification passes and that
this is the separate full-app build. Real iPhone/runtime verification is absent.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import sys
import zipfile

try:
    from .verify_roothide_build import check_ipa, ROOT, validate_macho, THIN_MAGICS, FAT_MAGICS
except ImportError:
    from verify_roothide_build import check_ipa, ROOT, validate_macho, THIN_MAGICS, FAT_MAGICS


EXPERIMENTAL_BUNDLE_ID = "com.gokuencinar.roothide3.fulltest"
EXPERIMENTAL_DISPLAY_NAME = "RootHide 3 Experimental"
HARDWARE_BETA_BUNDLE_ID = "com.gokuencinar.roothide3.hardwarebeta"
HARDWARE_BETA_DISPLAY_NAME = "RootHide 3 Hardware Beta"
GUARD_MARKER = b"RH3_FULL_APP_EXPERIMENTAL_GUARDED_V1"
DISABLED_MARKER = b"RH3_JAILBREAK_DISABLED_V1"
ACTIVE_MARKER = b"RH3_HARDWARE_BETA_ACTIVATED_V1"


def check_full_identity(archive, *, hardware_beta=False):
    """Identity, separation and defensive ZIP validation (portable fixture)."""
    errors = []
    contents = archive.infolist()
    names = [member.filename for member in contents]
    prefix = "Payload/Dopamine.app/"
    if len(names) != len(set(names)):
        errors.append("Duplicate ZIP members")
    if any(name.startswith("/") or "\\" in name or
           any(piece in {".", "..", ""} for piece in name.rstrip("/").split("/"))
           for name in names):
        errors.append("Unsafe ZIP member path")
    if any(not name.startswith(prefix) and name not in
           {"Payload/", "Payload/Dopamine.app/"} for name in names):
        errors.append("Unexpected content outside full experimental app")
    if archive.testzip() is not None:
        errors.append("ZIP CRC check failed")
    info_path = prefix + "Info.plist"
    binary_path = prefix + "Dopamine"
    if info_path not in names or binary_path not in names:
        return errors + ["Missing full app executable or Info.plist"], {}
    info = plistlib.loads(archive.read(info_path))
    details = {
        "bundle_id": info.get("CFBundleIdentifier"),
        "display_name": info.get("CFBundleDisplayName"),
        "executable_sha256": hashlib.sha256(archive.read(binary_path)).hexdigest(),
    }
    expected_id = HARDWARE_BETA_BUNDLE_ID if hardware_beta else EXPERIMENTAL_BUNDLE_ID
    expected_display = HARDWARE_BETA_DISPLAY_NAME if hardware_beta else EXPERIMENTAL_DISPLAY_NAME
    if details["bundle_id"] != expected_id:
        errors.append("Full experiment has incorrect or stock bundle identifier")
    if details["display_name"] != expected_display:
        errors.append("Full experiment has incorrect display name")
    if info.get("CFBundleExecutable") != "Dopamine":
        errors.append("Full experiment has unexpected executable")
    if GUARD_MARKER not in archive.read(binary_path):
        errors.append("Full experiment lacks its compile-time safety marker")
    expected_marker = ACTIVE_MARKER if hardware_beta else DISABLED_MARKER
    forbidden_marker = DISABLED_MARKER if hardware_beta else ACTIVE_MARKER
    if expected_marker not in archive.read(binary_path):
        errors.append("Full experiment does not match expected bootstrap activation marker")
    if forbidden_marker in archive.read(binary_path):
        errors.append("Full experiment contains contradictory bootstrap activation markers")
    return errors, details


def check_embedded_deployment(archive):
    """Reject bundled code with a newer minimum OS than the enclosing app."""
    errors, checked = [], 0
    try:
        info = plistlib.loads(archive.read("Payload/Dopamine.app/Info.plist"))
        parts = str(info.get("MinimumOSVersion", "")).split(".")
        if not 1 <= len(parts) <= 3 or not all(p.isdigit() for p in parts):
            raise ValueError("Missing valid MinimumOSVersion")
        version = [int(p) for p in parts] + [0] * (3 - len(parts))
        app_minimum = (version[0] << 16) | (version[1] << 8) | version[2]
        for member in archive.infolist():
            if member.is_dir() or not member.filename.startswith("Payload/Dopamine.app/"):
                continue
            with archive.open(member) as stream:
                magic = stream.read(4)
                if magic not in THIN_MAGICS and magic not in FAT_MAGICS:
                    continue
                content = magic + stream.read()
            structural_error = validate_macho(content)
            if structural_error:
                errors.append(f"Invalid embedded Mach-O {member.filename}: {structural_error}")
                continue
            slices = [memoryview(content)]
            if magic in FAT_MAGICS:
                endian, fat64 = FAT_MAGICS[magic]
                slices = []
                for i in range(struct.unpack_from(endian + "I", content, 4)[0]):
                    entry = 8 + i * (32 if fat64 else 20)
                    offset, size = struct.unpack_from(endian + ("QQ" if fat64 else "II"), content, entry + 8)
                    slices.append(memoryview(content)[offset:offset + size])
            for data in slices:
                endian = THIN_MAGICS[bytes(data[:4])]
                cursor, minimums = 32, []
                for _ in range(struct.unpack_from(endian + "I", data, 16)[0]):
                    cmd, size = struct.unpack_from(endian + "II", data, cursor)
                    if cmd == 0x32:
                        if size < 24:
                            raise ValueError(f"Truncated LC_BUILD_VERSION: {member.filename}")
                        platform, minimum = struct.unpack_from(endian + "II", data, cursor + 8)
                        if platform != 2:
                            errors.append(f"Non-iOS platform in {member.filename}")
                        minimums.append(minimum)
                    elif cmd == 0x25:
                        if size < 16:
                            raise ValueError(f"Truncated LC_VERSION_MIN_IPHONEOS: {member.filename}")
                        minimums.append(struct.unpack_from(endian + "I", data, cursor + 8)[0])
                    cursor += size
                checked += 1
                if not minimums:
                    errors.append(f"Missing minimum iOS in {member.filename}")
                elif max(minimums) > app_minimum:
                    errors.append(f"Embedded code requires a newer iOS than the app: {member.filename}")
    except (KeyError, ValueError, struct.error, plistlib.InvalidFileException) as exc:
        errors.append(f"Unable to verify embedded deployment: {exc}")
    return errors, checked


def inspect_ipa(path, *, hardware_beta=False):
    errors, details = check_ipa(path)
    if not path.is_file():
        return errors, details
    try:
        with zipfile.ZipFile(path) as archive:
            identity_errors, identity_details = check_full_identity(archive, hardware_beta=hardware_beta)
            errors.extend(identity_errors)
            details.update(identity_details)
            deployment_errors, checked = check_embedded_deployment(archive)
            errors.extend(deployment_errors)
            details["embedded_macho_slices_checked"] = checked
    except (OSError, ValueError, zipfile.BadZipFile, plistlib.InvalidFileException) as exc:
        errors.append(f"Invalid experimental IPA: {exc}")
    source = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(encoding="utf-8")
    if "#define ROOTHIDE3_BOOTSTRAP_READY 0" not in source:
        errors.append("RootHide safety gate was modified")
    return errors, details


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipa", type=Path, default=Path("Application/RootHide3-Full-Experimental.ipa"))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--hardware-beta", action="store_true",
                        help="Explicitly verify a manually activated, untested hardware beta")
    args = parser.parse_args()
    errors, details = inspect_ipa(args.ipa, hardware_beta=args.hardware_beta)
    report = {
        "status": "PASS" if not errors else "FAIL",
        "classification": ("UNTESTED HARDWARE BETA / DANGEROUS JAILBREAK ENABLED"
                           if args.hardware_beta else
                           "FULL DOPAMINE PORT / ROOT HIDE JAILBREAK DISABLED"),
        "details": details,
        "errors": errors,
        "apple_provisioning_verified": False,
        "device_bootstrap_verified": False,
        "roothide_runtime_enabled": args.hardware_beta,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(report["status"], report["classification"])
        for error in errors:
            print(" -", error, file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
