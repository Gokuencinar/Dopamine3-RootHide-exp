"""Contracts for the two launch blockers found in the 2026-10-14 audit.

Boomerang checks resolve the actual production domain table and numeric IDs.
When a C compiler is present (e.g. macOS CI), the trustcache cases execute
the exact production C parser function against valid/malformed file fixtures.
Neither test family establishes on-device kernel or launchd correctness.
"""

import ctypes
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class BoomerangContractTests(unittest.TestCase):
    def test_root_actions_resolve_to_real_boomerang_handlers(self):
        header = read("BaseBin/libjailbreak/src/jbserver_domains.h")
        root_domain = int(re.search(r"#define\s+JBS_DOMAIN_ROOT\s+(\d+)", header).group(1))
        source = read("BaseBin/libjailbreak/src/jbserver_boomerang.c")
        max_domain_expr = re.search(r"struct jbserver_impl gBoomerangServer\s*=\s*\{.*?\.maxDomain\s*=\s*([\w]+)", source, re.S).group(1)
        max_domain = root_domain if max_domain_expr == "JBS_DOMAIN_ROOT" else int(max_domain_expr)
        table = re.search(r"\.domains\s*=\s*\(struct jbserver_domain\*\[\]\)\s*\{([^}]*)\}", source, re.S).group(1)
        domains = re.findall(r"&([\w]+)|\bNULL\b", table)
        slots = [name or None for name in domains]

        # Model the exact indexing and bounds contract of jbserver.c; an
        # earlier guard rejected Root=4 because Boomerang maxDomain was 1.
        def route(domain_id, action_id):
            if domain_id < 1 or domain_id > max_domain:
                return None
            if slots[domain_id - 1] != "gBoomerangDomain":
                return None
            return {
                1: "boomerang_get_physrw",
                2: "boomerang_sign_thread",
                3: "boomerang_get_sysinfo",
            }.get(action_id)

        self.assertEqual(root_domain, 4)
        self.assertEqual(max_domain, root_domain)
        self.assertEqual(slots[root_domain - 1], "gBoomerangDomain")
        self.assertIn(".handler = boomerang_get_physrw", source)
        self.assertIn(".handler = boomerang_sign_thread", source)
        self.assertIn(".handler = boomerang_get_sysinfo", source)
        for action_id, handler in enumerate(("boomerang_get_physrw", "boomerang_sign_thread", "boomerang_get_sysinfo"), 1):
            with self.subTest(root_action=action_id):
                self.assertEqual(route(root_domain, action_id), handler)
        for domain_id, action_id in ((0, 1), (1, 1), (2, 1), (3, 1), (5, 1), (999, 1), (4, 0), (4, 4), (4, 42)):
            with self.subTest(invalid=(domain_id, action_id)):
                self.assertIsNone(route(domain_id, action_id))

    def test_out_of_band_done_uses_root_domain_and_permissions(self):
        source = read("BaseBin/libjailbreak/src/jbserver_boomerang.c")
        done = source[source.index("int jbserver_received_boomerang_xpc_message("):]
        self.assertIn("domain == JBS_DOMAIN_ROOT && action == JBS_BOOMERANG_DONE", done)
        self.assertIn("boomerang_domain_allowed(caller)", done)
        self.assertIn("if (!domainValue || !actionValue", done)


class TrustcacheContractTests(unittest.TestCase):
    def test_archive_cache_is_preserved_and_checked_before_rollback(self):
        source = read("Application/Dopamine/Jailbreak/DOBootstrapper.m")
        install = source[source.index("- (NSError *)rh3InstallBasebinAtRoot:"):source.index("- (NSError *)rh3InstallDependenciesAtRoot:")]
        loader = read("Application/Dopamine/Jailbreak/DOJailbreaker.m")
        self.assertNotIn("removeItemAtPath:[oldBasebin stringByAppendingPathComponent:@\"basebin.tc\"]", install)
        self.assertIn("lstat(trustcache.fileSystemRepresentation, &trustcacheInfo)", install)
        self.assertIn("S_ISREG(trustcacheInfo.st_mode)", install)
        self.assertLess(install.index("lstat(trustcache.fileSystemRepresentation"),
                        install.index("if (error) {\n        NSError *rollbackError"))
        self.assertIn('trustcache_file_build_from_path(JBROOT_PATH("/basebin/basebin.tc")', loader)
        self.assertIn("trustcache_file_upload_with_uuid(basebinTcFile, BASEBIN_TRUSTCACHE_UUID)", loader)
        self.assertLess(loader.index("*errOut = [self loadBasebinTrustcache]"),
                        loader.index("*errOut = [self injectLaunchdHook]"))


class NativeTrustcacheParserTests(unittest.TestCase):
    """Builds only the extracted production parser with portable type stubs.

    No iOS SDK or device is required; tests execute on a macOS or Linux host.
    """

    @classmethod
    def setUpClass(cls):
        if sys.platform == "win32":
            raise unittest.SkipTest("No native C compiler in the Windows test environment")
        compiler = shutil.which("clang") or shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("No C compiler available")
        cls.temp = tempfile.TemporaryDirectory(prefix="rh3-cache-test-")
        cls.addClassCleanup(cls.temp.cleanup)
        src = read("BaseBin/libjailbreak/src/trustcache.c")
        start = src.index("int trustcache_file_build_from_path(")
        end = src.index("\nbool trustcache_contains_cdhash(", start)
        function = src[start:end]
        prefix = """
            #include <stddef.h>
            #include <stdint.h>
            #include <stdlib.h>
            #include <stdio.h>
            #include <sys/types.h>
            #include <sys/stat.h>
            #include <unistd.h>
            #include <fcntl.h>
            #include <errno.h>
            typedef struct { uint8_t hash[20]; uint8_t hash_type; uint8_t flags; }
                __attribute__((packed)) trustcache_entry_v1;
            typedef struct { uint32_t version; uint8_t uuid[16]; uint32_t length;
                trustcache_entry_v1 entries[]; } __attribute__((packed)) trustcache_file_v1;
        """
        cpath = Path(cls.temp.name) / "cache_test.c"
        cpath.write_text(prefix + function, encoding="utf-8")
        libpath = Path(cls.temp.name) / ("libcache.dylib" if sys.platform == "darwin" else "libcache.so")
        cmd = [compiler, "-std=c11", "-D_DARWIN_C_SOURCE", "-D_DEFAULT_SOURCE", "-fPIC",
               "-dynamiclib" if sys.platform == "darwin" else "-shared", str(cpath), "-o", str(libpath)]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cls.lib = ctypes.CDLL(str(libpath))
        cls.parser = cls.lib.trustcache_file_build_from_path
        cls.parser.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        cls.parser.restype = ctypes.c_int
        cls.free = ctypes.CDLL(None).free
        cls.free.argtypes = [ctypes.c_void_p]

    def parse(self, data: bytes, as_symlink=False):
        path = Path(self.temp.name) / ("fixture-" + str(id(data)))
        path.write_bytes(data)
        if as_symlink:
            link = path.with_suffix(".link")
            link.symlink_to(path)
            path = link
        result = ctypes.c_void_p()
        status = self.parser(os.fsencode(path), ctypes.byref(result))
        if result.value:
            self.free(result)
        return status, bool(result.value)

    def test_valid_serialized_cache(self):
        entry = b"\x11" * 20 + b"\x02\x00"
        data = struct.pack("<I", 1) + bytes(16) + struct.pack("<I", 2) + entry * 2
        self.assertEqual(self.parse(data), (0, True))

    def test_rejects_invalid_version_length_short_file_symlink_and_oversized(self):
        entry = b"\x11" * 20 + b"\x02\x00"
        good = struct.pack("<I", 1) + bytes(16) + struct.pack("<I", 1) + entry
        fixtures = (
            struct.pack("<I", 2) + good[4:],        # version
            good[:20] + struct.pack("<I", 999999) + entry,  # claimed count
            good[:-1],                                # truncated entry
            good[:8],                                 # truncated header
            good + bytes(0x4000),                     # oversized file
        )
        for data in fixtures:
            with self.subTest(size=len(data)):
                self.assertEqual(self.parse(data), (-1, False))
        self.assertEqual(self.parse(good, as_symlink=True), (-1, False))


if __name__ == "__main__":
    unittest.main()
