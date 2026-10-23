"""Protect app metadata inspection from sandbox and vendor UID false negatives.

Source checks cannot replace runtime LaunchServices validation on an iPhone.
"""
from io import BytesIO
from pathlib import Path
import lzma
import tarfile
import unittest

from tools.tests.test_roothide_managers_r173 import deb_members


ROOT = Path(__file__).resolve().parents[2]
ENV = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m"


class AppScopeReferenceTests(unittest.TestCase):
    def test_refresh_parses_rooted_plists_before_restoring_sandbox(self):
        source = ENV.read_text(encoding="utf-8")
        body = source.split("- (int)refreshJailbreakApps", 1)[1].split(
            "// Return a coarse category", 1)[0]
        privileged, unprivileged = body.split("        }];", 1)
        self.assertIn("dictionaryWithContentsOfFile", privileged)
        self.assertNotIn("dictionaryWithContentsOfFile", unprivileged)
        self.assertNotIn("LSApplicationProxy applicationProxyForIdentifier", privileged)
        self.assertIn("LSApplicationProxy applicationProxyForIdentifier", unprivileged)

    def test_comprehensive_inventory_does_all_file_io_before_privilege_drop(self):
        source = ENV.read_text(encoding="utf-8")
        body = source.split("- (int)diagnoseRootHideComprehensive", 1)[1].split(
            "// Explicit, opt-in repair", 1)[0]
        privileged, unprivileged = body.split("    }];", 1)
        for access in ("lstat(plist.fileSystemRepresentation", "RH3DiagnosticMachMagic([bundle",
                       "RH3DiagnosticAppBacklink(bundle)"):
            self.assertIn(access, privileged)
            self.assertNotIn(access, unprivileged)
        self.assertNotIn("LSApplicationProxy applicationProxyForIdentifier", privileged)
        self.assertIn("LSApplicationProxy applicationProxyForIdentifier", unprivileged)
        self.assertIn("plist_uid0", body)  # Ownership remains explicit, not a fake absence.

    def test_bundled_manager_plists_can_be_owned_by_mobile(self):
        for filename, expected_uid in (("roothide_sileo.deb", 0),
                                       ("roothide_zebra.deb", 501),
                                       ("roothideapp.deb", 501)):
            with self.subTest(filename=filename):
                archive = deb_members((ROOT / "Application/Dopamine/Resources" / filename).read_bytes())
                name = next(name for name in archive if name.startswith("data.tar."))
                content = lzma.decompress(archive[name]) if name.endswith(".lzma") else archive[name]
                with tarfile.open(fileobj=BytesIO(content), mode="r:*") as tar:
                    entry = next(x for x in tar if x.name.endswith(".app/Info.plist"))
                    self.assertEqual(entry.uid, expected_uid)


if __name__ == "__main__":
    unittest.main()
