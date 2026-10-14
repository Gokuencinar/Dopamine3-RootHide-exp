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
import sys
import zipfile

try:
    from .verify_roothide_build import check_ipa, ROOT
except ImportError:
    from verify_roothide_build import check_ipa, ROOT


EXPERIMENTAL_BUNDLE_ID = "com.gokuencinar.roothide3.fulltest"
EXPERIMENTAL_DISPLAY_NAME = "RootHide 3 Experimental"
GUARD_MARKER = b"RH3_FULL_APP_EXPERIMENTAL_GUARDED_V1"


def check_full_identity(archive):
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
    if details["bundle_id"] != EXPERIMENTAL_BUNDLE_ID:
        errors.append("Full experiment has incorrect or stock bundle identifier")
    if details["display_name"] != EXPERIMENTAL_DISPLAY_NAME:
        errors.append("Full experiment has incorrect display name")
    if info.get("CFBundleExecutable") != "Dopamine":
        errors.append("Full experiment has unexpected executable")
    if GUARD_MARKER not in archive.read(binary_path):
        errors.append("Full experiment lacks its compile-time safety marker")
    return errors, details


def inspect_ipa(path):
    errors, details = check_ipa(path)
    if not path.is_file():
        return errors, details
    try:
        with zipfile.ZipFile(path) as archive:
            identity_errors, identity_details = check_full_identity(archive)
            errors.extend(identity_errors)
            details.update(identity_details)
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
    args = parser.parse_args()
    errors, details = inspect_ipa(args.ipa)
    report = {
        "status": "PASS" if not errors else "FAIL",
        "classification": "FULL DOPAMINE PORT / ROOT HIDE JAILBREAK DISABLED",
        "details": details,
        "errors": errors,
        "apple_provisioning_verified": False,
        "device_bootstrap_verified": False,
        "roothide_runtime_enabled": False,
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
