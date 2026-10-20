#!/usr/bin/env python3
"""Check bundled CPU slices, independently of the Debian package ABI name."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

try:
    from .verify_roothide_build import ROOT, PINNED_RESOURCES, THIN_MAGICS, FAT_MAGICS, validate_macho
except ImportError:
    from verify_roothide_build import ROOT, PINNED_RESOURCES, THIN_MAGICS, FAT_MAGICS, validate_macho


def decompress(data):
    try:
        import zstandard
    except ImportError:
        return subprocess.run(["zstd", "-d", "-c"], input=data,
                              capture_output=True, check=True).stdout
    return zstandard.ZstdDecompressor().decompress(data, max_output_size=512 * 1024 * 1024)


def deb_payload(data):
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("Invalid Debian archive")
    offset = 8
    payloads = []
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            raise ValueError("Invalid ar member")
        size = int(header[48:58])
        if size < 0 or offset + 60 + size > len(data):
            raise ValueError("Truncated ar member")
        name = header[:16].decode("ascii").strip().rstrip("/")
        payload = data[offset + 60:offset + 60 + size]
        if name.startswith("data.tar"):
            payloads.append(decompress(payload) if name.endswith(".zst") else payload)
        offset += 60 + size + size % 2
    if len(payloads) != 1:
        raise ValueError("Expected exactly one Debian payload")
    return payloads[0]


def check_payload(data, label):
    count = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            if not member.isfile():
                continue
            with archive.extractfile(member) as stream:
                content = stream.read()
            if content[:4] not in THIN_MAGICS and content[:4] not in FAT_MAGICS:
                continue
            error = validate_macho(content, required_arch="arm64")
            if error:
                raise ValueError(f"{label}:{member.name}: {error}")
            count += 1
    if not count:
        raise ValueError(f"{label}: no Mach-O executables found")
    return count


def check_empty_provider_payload(data):
    # The official libkrw0-dummy has only dpkg metadata. It must NEVER gain
    # executable payload, symlinks or paths affecting the jailbreak root.
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            if not member.isdir():
                raise ValueError(f"libkrw virtual provider has unexpected payload: {member.name}")


def main():
    results = []
    resources = ROOT / "Application/Dopamine/Resources"
    for name, expected in PINNED_RESOURCES.items():
        data = (resources / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"{name}: unexpected asset hash")
        payload = deb_payload(data) if name.endswith(".deb") else decompress(data)
        if name == "roothide_libkrw0_dummy.deb":
            check_empty_provider_payload(payload)
            results.append(dict(asset=name, sha256=expected, arm64_macho_files=0, metadata_only=True))
            continue
        count = check_payload(payload, name)
        results.append(dict(asset=name, sha256=expected, arm64_macho_files=count))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()

