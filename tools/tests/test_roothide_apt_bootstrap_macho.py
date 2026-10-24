"""Inspect the actual bundled APT Mach-O/signature dependency in host CI.

This deliberately parses data from the original 1900 bootstrap rather than
asserting that a DLL is present solely because a package name is in dpkg.
No files on a device or bootstrap extraction directories are modified.
"""

import hashlib
import posixpath
from pathlib import Path
import shutil
import struct
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / "Application/Dopamine/Resources/roothide_bootstrap_1900.tar.zst"
HTTP = "./usr/libexec/apt/methods/http"
GNUTLS = "./usr/lib/libgnutls.30.dylib"


def macho_commands(data):
    if len(data) < 32 or struct.unpack_from("<I", data)[0] != 0xFEEDFACF:
        raise ValueError("expected thin little-endian arm64 Mach-O")
    _, cpu, _, _, count, size, _, _ = struct.unpack_from("<IiiIIIII", data)
    if cpu != 0x0100000C or 32 + size > len(data):
        raise ValueError("unexpected CPU or truncated load commands")
    off = 32
    for _ in range(count):
        if off + 8 > 32 + size:
            raise ValueError("truncated load command")
        command, length = struct.unpack_from("<II", data, off)
        if length < 8 or off + length > 32 + size:
            raise ValueError("invalid load command")
        yield command, data[off:off + length]
        off += length


def command_paths(data, cmd_ids):
    paths = []
    for command, blob in macho_commands(data):
        if command not in cmd_ids:
            continue
        offset = struct.unpack_from("<I", blob, 8)[0]
        if offset >= len(blob):
            raise ValueError("invalid dylib/rpath string offset")
        paths.append(blob[offset:].split(b"\0", 1)[0].decode("utf-8"))
    return paths


def code_directories(data):
    found = []
    for cmd, blob in macho_commands(data):
        if cmd == 0x1D:  # LC_CODE_SIGNATURE
            offset, size = struct.unpack_from("<II", blob, 8)
            if offset + size > len(data):
                raise ValueError("truncated code signature")
            sig = data[offset:offset + size]
            magic, length, count = struct.unpack_from(">III", sig)
            if magic != 0xFADE0CC0 or length > len(sig) or 12 + count * 8 > length:
                raise ValueError("invalid SuperBlob")
            for i in range(count):
                kind, suboff = struct.unpack_from(">II", sig, 12 + i * 8)
                if kind != 0 and not 0x1000 <= kind < 0x1005:
                    continue
                if suboff + 44 > length:
                    raise ValueError("invalid CodeDirectory location")
                dmagic, dlen = struct.unpack_from(">II", sig, suboff)
                if dmagic != 0xFADE0C02 or suboff + dlen > length:
                    raise ValueError("invalid CodeDirectory blob")
                cd = sig[suboff:suboff + dlen]
                # Layout: magic, length, version, flags, hashOffset,
                # identOffset, nSpecialSlots, nCodeSlots, codeLimit.
                hash_offset = struct.unpack_from(">I", cd, 16)[0]
                nslots = struct.unpack_from(">I", cd, 28)[0]
                limit = struct.unpack_from(">I", cd, 32)[0]
                hashsize, hashtype, _, pageshift = struct.unpack_from("BBBB", cd, 36)
                if hashtype not in (1, 2, 3, 4) or pageshift not in (0, 12, 14):
                    raise ValueError("unsupported hash/page geometry")
                if hash_offset + nslots * hashsize > len(cd) or not limit:
                    raise ValueError("CodeDirectory code slots outside bounds")
                found.append((cd, hash_offset, nslots, limit, hashsize, hashtype, pageshift))
    return found


def valid_code_pages(data, directory):
    cd, hashes, count, limit, size, typ, pageshift = directory
    page_size = (1 << pageshift) if pageshift else limit
    if (limit + page_size - 1) // page_size != count:
        return False
    for index in range(count):
        start = index * page_size
        block = data[start:min(start + page_size, limit)]
        if len(block) != min(page_size, limit - start):
            return False
        digest = {1: hashlib.sha1, 2: hashlib.sha256, 3: hashlib.sha256,
                  4: hashlib.sha384}[typ](block).digest()[:size]
        if digest != cd[hashes + index * size:hashes + (index + 1) * size]:
            return False
    return True


class AptBootstrapMachOTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tar = shutil.which("tar")
        if not tar or not ARCHIVE.is_file():
            raise unittest.SkipTest("bootstrap archive or tar is unavailable")
        cls.files = {}
        for path in (HTTP, GNUTLS):
            result = subprocess.run([tar, "-xOf", str(ARCHIVE), path],
                                    capture_output=True, timeout=40)
            if result.returncode != 0:
                raise unittest.SkipTest("tar cannot extract zstd: " +
                                        result.stderr.decode(errors="replace")[:200])
            cls.files[path] = result.stdout

    def test_http_refers_to_bundled_gnutls(self):
        http = self.files[HTTP]
        dependencies = command_paths(http, {0xC, 0x18, 0x80000018})
        self.assertIn("@rpath/libgnutls.30.dylib", dependencies)
        self.assertIn("libgnutls.30.dylib", GNUTLS)
        rpaths = command_paths(http, {0x8000001C})
        self.assertIn("@loader_path/.jbroot/usr/lib", rpaths)
        self.assertIn("@loader_path/.jbroot/usr/local/lib", rpaths)

    def test_original_code_signatures_are_page_consistent(self):
        for path, data in self.files.items():
            with self.subTest(path=path):
                directories = code_directories(data)
                self.assertTrue(directories, "missing CodeDirectory")
                self.assertTrue(all(valid_code_pages(data, cd) for cd in directories))

    def test_http_and_gnutls_are_adhoc_dependencies_for_recursive_trust(self):
        for path, data in self.files.items():
            with self.subTest(path=path):
                directories = code_directories(data)
                self.assertTrue(directories)
                # code-directory flags at byte 12: 0x2 is CS_ADHOC.
                self.assertTrue(all(struct.unpack_from(">I", cd[0], 12)[0] & 2
                                    for cd in directories))

    def test_http_and_gnutls_rpath_dependencies_exist_in_1900_bootstrap(self):
        tar = shutil.which("tar")
        result = subprocess.run([tar, "-tf", str(ARCHIVE)], capture_output=True,
                                text=True, timeout=40)
        self.assertEqual(result.returncode, 0, result.stderr[:200])
        packaged = set(result.stdout.splitlines())
        for path, data in self.files.items():
            dependencies = command_paths(data, {0xC, 0x18, 0x80000018,
                                                0x1F, 0x8000001F})
            for dependency in dependencies:
                if dependency.startswith("@rpath/"):
                    name = dependency[len("@rpath/"):]
                    with self.subTest(binary=path, dependency=name):
                        self.assertTrue("./usr/lib/" + name in packaged or
                                        "./usr/local/lib/" + name in packaged)

    def test_original_apt_backlinks_are_packaged_and_point_inside_root(self):
        """An intact bootstrap needs no repair of the APT HTTP methods backlink."""
        result = subprocess.run([shutil.which("tar"), "-tvf", str(ARCHIVE)],
                                capture_output=True, text=True, timeout=40)
        self.assertEqual(result.returncode, 0, result.stderr[:200])
        links = {}
        for entry in result.stdout.splitlines():
            if not entry.startswith("l") or " -> " not in entry:
                continue
            before, target = entry.rsplit(" -> ", 1)
            member = before.split()[-1]
            links[member] = target

        # The initial archive already contains a root marker and per-directory
        # relative links. Verify the chain without extracting or mutating it.
        self.assertEqual(links.get("./.jbroot"), ".")
        self.assertEqual(links.get("./usr/libexec/apt/methods/.jbroot"),
                         "../../../../.jbroot")
        self.assertEqual(links.get("./usr/lib/.jbroot"), "../../.jbroot")
        for member in ("./usr/libexec/apt/methods/.jbroot", "./usr/lib/.jbroot"):
            dest = posixpath.normpath(posixpath.join(posixpath.dirname(member), links[member]))
            self.assertEqual(dest, ".jbroot")

    def test_corrupting_page_zero_is_detected_not_trusted(self):
        data = bytearray(self.files[GNUTLS])
        directory = code_directories(data)[0]
        self.assertTrue(valid_code_pages(data, directory))
        # The RootHide brand writes bytes within the first __TEXT page.
        data[240] ^= 0x40
        self.assertFalse(valid_code_pages(data, directory))


if __name__ == "__main__":
    unittest.main()
