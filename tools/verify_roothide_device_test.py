"""Inspect a RootHide 3 GUI-only diagnostic IPA, not a functional jailbreak.

Ad-hoc ldid signatures are not equivalent to an Apple provisioning profile.
This check validates ZIP structure, a dedicated UIKit-only runtime marker,
identifiers and Mach-O layout. It cannot establish device installability.
"""

import argparse
import json
from pathlib import Path
import plistlib
import stat
import sys
import zipfile

try:
    from .verify_roothide_build import validate_macho
except ImportError:  # Run directly from tools/ during GitHub Actions.
    from verify_roothide_build import validate_macho


EXPECTED_BUNDLE_ID = "com.gokuencinar.roothide3.diagnostic"
EXPECTED_DISPLAY_NAME = "RootHide 3 Test"
EXPECTED_BINARY_MARKER = b"RH3_DEVICE_TEST_UIKIT_ONLY_V1"


def inspect_ipa(path: Path):
    errors = []
    details = {"ipa": str(path), "mode": "GUI-only; jailbreak disabled"}
    if not path.is_file():
        return ["Diagnostic IPA does not exist"], details
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            contents = set(names)
            if len(names) != len(contents):
                errors.append("Duplicate ZIP entry names are not allowed")
            prefix = "Payload/Dopamine.app/"
            info_path = prefix + "Info.plist"
            binary_path = prefix + "Dopamine"
            allowed = {"Payload/", "Payload/Dopamine.app/", info_path, binary_path}
            for member in members:
                name = member.filename
                file_type = (member.external_attr >> 16) & 0o170000
                if name not in allowed:
                    errors.append(f"Unexpected ZIP entry: {name}")
                if (name.startswith("/") or "\\" in name or "//" in name or
                    any(piece in {".", "..", ""} for piece in name.rstrip("/").split("/"))):
                    errors.append(f"Unsafe ZIP path: {name}")
                if file_type == stat.S_IFLNK:
                    errors.append(f"ZIP symbolic link is forbidden: {name}")
                if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    errors.append(f"Unsupported ZIP member type: {name}")
                if name.endswith("/") != (name in {"Payload/", "Payload/Dopamine.app/"}):
                    errors.append(f"Unexpected ZIP directory or file type: {name}")
            damaged = archive.testzip()
            if damaged:
                errors.append(f"ZIP CRC failed for {damaged}")
            if info_path not in contents or binary_path not in contents:
                return ["Missing app Info.plist or executable"], details
            info = plistlib.loads(archive.read(info_path))
            details["bundle_id"] = info.get("CFBundleIdentifier")
            details["display_name"] = info.get("CFBundleDisplayName")
            details["minimum_os"] = info.get("MinimumOSVersion")
            if details["bundle_id"] != EXPECTED_BUNDLE_ID:
                errors.append("Diagnostic bundle ID is not isolated from stock Dopamine")
            if details["display_name"] != EXPECTED_DISPLAY_NAME:
                errors.append("Diagnostic display name is not distinct")
            if info.get("CFBundleExecutable") != "Dopamine":
                errors.append("Unexpected diagnostic bundle executable")
            if info.get("CFBundlePackageType") != "APPL":
                errors.append("Diagnostic bundle is not an iOS application")
            binary = archive.read(binary_path)
            macho_error = validate_macho(binary, required_arch="arm64")
            if macho_error:
                errors.append(f"Invalid diagnostic Mach-O: {macho_error}")
            if EXPECTED_BINARY_MARKER not in binary:
                errors.append("Binary does not contain the standalone UIKit-only diagnostic marker")
            # No extensions, frameworks, archives, scripts or embedded jailbreak
            # resources should be present: the app comprises exactly two files.
            unexpected = sorted(name for name in contents if name.startswith(prefix)
                                and not name.endswith("/") and name not in {info_path, binary_path})
            if unexpected:
                errors.append(f"Unexpected files in standalone diagnostic IPA: {unexpected}")
            # Check all app subdirectories, not just its top-level Resources.
            # A nested installer must never slip into a GUI-only archive.
            forbidden = ("basebin.tar", ".deb", ".tar.zst")
            found = sorted(name for name in contents if name.startswith(prefix)
                           and not name.endswith("/") and name.lower().endswith(forbidden))
            if found:
                errors.append(f"Diagnostic bundles jailbreak installer payloads: {found}")
            # No signature or entitlement conclusions: those must be checked
            # against the actual signed app on the target device.
    except (OSError, ValueError, zipfile.BadZipFile, plistlib.InvalidFileException) as exc:
        errors.append(f"Could not inspect diagnostic IPA: {exc}")
    return errors, details


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipa", type=Path, default=Path("Application/RootHide3-Device-Test.ipa"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    errors, details = inspect_ipa(args.ipa)
    report = {"status": "PASS" if not errors else "FAIL", "details": details,
              "errors": errors, "apple_provisioning_verified": False,
              "roothide_jailbreak_enabled": False}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(report["status"], errors)
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
