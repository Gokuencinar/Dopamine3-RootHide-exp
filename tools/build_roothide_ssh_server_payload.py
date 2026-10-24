#!/usr/bin/env python3
"""Rebuild only the pinned RootHide 1900 OpenSSH server deb with safer startup.

Offline, deterministic input: never download or overwrite an original .deb.
Run with Python zstandard installed; see docs/ROOTHIDE3-SSH-PACKAGE-2026-10-24.md.
"""

from __future__ import annotations

import argparse
import hashlib
import io
from pathlib import Path
import re
import tarfile

import zstandard as zstd

OFFICIAL_SHA256 = "7030f44fdbb1851cb6e702c02a60842dff54ac7fcabb80745bf34069757d9c6a"
SAFE_SHELL_SCRIPT = b"#!/bin/sh\n# OpenSSH must be prepared by the verified RootHide3 installer phase.\nexit 0\n"


def ar_members(data: bytes):
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("not a Debian ar archive")
    offset = 8
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise ValueError("invalid Debian ar header")
        name = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58])
        payload = data[offset + 60:offset + 60 + size]
        if len(payload) != size:
            raise ValueError("short Debian ar payload")
        yield name, payload
        offset += 60 + size + (size % 2)


def pack_ar(items):
    result = bytearray(b"!<arch>\n")
    for name, body in items:
        if len(name) > 15:
            raise ValueError("ar member name too long")
        header = (f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{0o100644:o}{' ' * 2}{len(body):<10}`\n")
        assert len(header) == 60
        result.extend(header.encode("ascii"))
        result.extend(body)
        if len(body) % 2:
            result.extend(b"\n")
    return bytes(result)


def transform_tar(payload: bytes, *, control: bool, config_md5: str | None = None):
    # The original archive has no hardlinks/symlink targets needing rewriting;
    # retain every member's metadata (uid/gid/mode/mtime/path/links).
    raw = zstd.ZstdDecompressor().stream_reader(io.BytesIO(payload)).read()
    members = []
    found = set()
    new_config_md5 = None
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as source:
        for info in source:
            body = source.extractfile(info).read() if info.isfile() else None
            normalized = info.name.lstrip("./")
            if control and normalized in ("extrainst_", "prerm"):
                found.add(normalized)
                body = SAFE_SHELL_SCRIPT
            if control and normalized == "md5sums":
                if not config_md5:
                    raise ValueError("control rebuilt before modified configuration")
                body, replacements = re.subn(
                    rb"(?m)^[0-9a-f]{32}(?=  etc/ssh/sshd_config$)",
                    config_md5.encode("ascii"), body,
                )
                if replacements != 1:
                    raise ValueError("cannot update original config md5sums entry")
                found.add(normalized)
            if not control and normalized == "etc/ssh/sshd_config":
                found.add(normalized)
                if body.count(b"PermitRootLogin yes\n") != 1:
                    raise ValueError("unexpected SSH default root-login policy")
                if b"PasswordAuthentication no\n" in body:
                    raise ValueError("unexpected duplicate SSH password policy")
                body = body.replace(b"PermitRootLogin yes\n", b"PermitRootLogin prohibit-password\n")
                body += (b"\n# RootHide3 explicit opt-in: no password login until a verified secure configuration.\n"
                         b"PasswordAuthentication no\n"
                         b"KbdInteractiveAuthentication no\n"
                         b"PermitEmptyPasswords no\n")
                new_config_md5 = hashlib.md5(body).hexdigest()
            members.append((info, body))
    expected = {"extrainst_", "prerm", "md5sums"} if control else {"etc/ssh/sshd_config"}
    if found != expected:
        raise ValueError(f"incomplete upstream SSH payload: {found!r}, expected {expected!r}")
    dst = io.BytesIO()
    with tarfile.open(fileobj=dst, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for info, body in members:
            if body is not None:
                info.size = len(body)
            archive.addfile(info, io.BytesIO(body) if body is not None else None)
    return zstd.ZstdCompressor(level=15, write_content_size=True).compress(dst.getvalue()), new_config_md5


def build(source: Path, destination: Path):
    original = source.read_bytes()
    if hashlib.sha256(original).hexdigest() != OFFICIAL_SHA256:
        raise ValueError("upstream OpenSSH server package SHA-256 mismatch")
    parts = dict(ar_members(original))
    if set(parts) != {"debian-binary", "control.tar.zst", "data.tar.zst"} or parts["debian-binary"] != b"2.0\n":
        raise ValueError("unrecognized OpenSSH package layout")
    parts["data.tar.zst"], config_md5 = transform_tar(parts["data.tar.zst"], control=False)
    parts["control.tar.zst"], _ = transform_tar(parts["control.tar.zst"], control=True,
                                               config_md5=config_md5)
    output = pack_ar([(name, parts[name]) for name in ("debian-binary", "control.tar.zst", "data.tar.zst")])
    if destination.exists():
        raise ValueError("refusing to replace an already produced SSH payload")
    destination.write_bytes(output)
    print(f"original_sha256={OFFICIAL_SHA256}")
    print(f"modified_sha256={hashlib.sha256(output).hexdigest()}")
    print(f"modified_size={len(output)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    build(args.source, args.destination)
