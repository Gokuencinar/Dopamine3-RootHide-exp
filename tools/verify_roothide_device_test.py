"""Inspect a RootHide 3 GUI-only diagnostic IPA, not a functional jailbreak.

Ad-hoc ldid signatures are not equivalent to an Apple provisioning profile.
This check validates ZIP structure, identifiers, Mach-O layout and removal
of bootstrap payloads, but cannot establish device installability by itself.
"""

import argparse
import json
from pathlib import Path
import plistlib
import sys
import zipfile

try:
    from .verify_roothide_build import validate_macho
except ImportError:  # Run directly from tools/ during GitHub Actions.
    from verify_roothide_build import validate_macho


EXPECTED_BUNDLE_ID = "com.gokuencinar.roothide3.diagnostic"
EXPECTED_DISPLAY_NAME = "RootHide 3 Test"


def inspect_ipa(path: Path):
    errors = []
    details = {"ipa": str(path), "mode": "GUI-only; jailbreak disabled"}
    if not path.is_file():
        return ["Diagnostic IPA does not exist"], details
    try:
        with zipfile.ZipFile(path) as archive:
            contents = set(archive.namelist())
            prefix = "Payload/Dopamine.app/"
            info_path = prefix + "Info.plist"
            binary_path = prefix + "Dopamine"
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
            macho_error = validate_macho(archive.read(binary_path), required_arch="arm64")
            if macho_error:
                errors.append(f"Invalid diagnostic Mach-O: {macho_error}")
            forbidden = ("basebin.tar", ".deb", ".tar.zst")
            found = [name for name in contents if name.startswith(prefix)
                     and "/" not in name[len(prefix):].rstrip("/")
                     and name.endswith(forbidden)]
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
