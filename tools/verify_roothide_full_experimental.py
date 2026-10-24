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
ALL_ENABLED_DISPLAY_NAME = "RootHide 3 All Enabled Beta"
GUARD_MARKER = b"RH3_FULL_APP_EXPERIMENTAL_GUARDED_V1"
DISABLED_MARKER = b"RH3_JAILBREAK_DISABLED_V1"
ACTIVE_MARKER = b"RH3_HARDWARE_BETA_ACTIVATED_V1"
TWEAKS_ON_MARKER = b"RH3_TWEAKS_DEFAULT_ENABLED_V1"
TWEAKS_SAFE_MARKER = b"RH3_TWEAKS_DEFAULT_SAFE_V1"


def check_bundle_identifiers(archive):
    """Inspect the built plists, including nested frameworks and extensions."""
    errors, bundles, identifiers = [], {}, {}
    for name in archive.namelist():
        if not name.startswith("Payload/") or not name.endswith("/Info.plist"):
            continue
        bundle = name.rsplit("/", 1)[0]
        if not bundle.endswith((".app", ".framework", ".appex", ".xpc")):
            continue
        try:
            info = plistlib.loads(archive.read(name))
            identifier = info.get("CFBundleIdentifier")
            if not isinstance(identifier, str) or not identifier.strip() or "$" in identifier:
                raise ValueError("missing or unresolved CFBundleIdentifier")
            bundles[bundle] = identifier
            identifiers.setdefault(identifier, []).append(bundle)
        except (ValueError, AttributeError, plistlib.InvalidFileException) as exc:
            errors.append(f"Invalid bundle metadata {name}: {exc}")
    for identifier, paths in identifiers.items():
        if len(paths) > 1:
            errors.append(f"DuplicateIdentifier {identifier}: {', '.join(paths)}")
    return errors, bundles


def check_full_identity(archive, *, hardware_beta=False, all_enabled=False):
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
    bundle_errors, bundles = check_bundle_identifiers(archive)
    errors.extend(bundle_errors)
    info_path = prefix + "Info.plist"
    binary_path = prefix + "Dopamine"
    if info_path not in names or binary_path not in names:
        return errors + ["Missing full app executable or Info.plist"], {}
    info = plistlib.loads(archive.read(info_path))
    details = {
        "bundle_id": info.get("CFBundleIdentifier"),
        "display_name": info.get("CFBundleDisplayName"),
        "executable_sha256": hashlib.sha256(archive.read(binary_path)).hexdigest(),
        "bundle_identifiers": bundles,
    }
    expected_id = HARDWARE_BETA_BUNDLE_ID if hardware_beta else EXPERIMENTAL_BUNDLE_ID
    expected_display = (ALL_ENABLED_DISPLAY_NAME if all_enabled else
                        HARDWARE_BETA_DISPLAY_NAME if hardware_beta else EXPERIMENTAL_DISPLAY_NAME)
    if all_enabled and not hardware_beta:
        errors.append("Tweaks-on mode requires jailbreak-enabled hardware beta")
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
    if hardware_beta:
        expected_tweaks = TWEAKS_ON_MARKER if all_enabled else TWEAKS_SAFE_MARKER
        forbidden_tweaks = TWEAKS_SAFE_MARKER if all_enabled else TWEAKS_ON_MARKER
        if expected_tweaks not in archive.read(binary_path):
            errors.append("Full experiment lacks requested tweak injection default marker")
        if forbidden_tweaks in archive.read(binary_path):
            errors.append("Full experiment contains contradictory tweak injection defaults")
    elif TWEAKS_ON_MARKER in archive.read(binary_path):
        errors.append("Jailbreak-disabled full experiment claims tweaks enabled")
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


def inspect_ipa(path, *, hardware_beta=False, all_enabled=False):
    errors, details = check_ipa(path)
    if not path.is_file():
        return errors, details
    try:
        with zipfile.ZipFile(path) as archive:
            identity_errors, identity_details = check_full_identity(archive, hardware_beta=hardware_beta,
                                                                 all_enabled=all_enabled)
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
    parser.add_argument("--all-enabled", action="store_true",
                        help="Also require default tweak injection on a fresh experimental bootstrap")
    args = parser.parse_args()
    errors, details = inspect_ipa(args.ipa, hardware_beta=args.hardware_beta,
                                  all_enabled=args.all_enabled)
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
        "tweaks_default_enabled_on_fresh_bootstrap": args.all_enabled,
        "tweak_loader_runtime_verified": False,
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
