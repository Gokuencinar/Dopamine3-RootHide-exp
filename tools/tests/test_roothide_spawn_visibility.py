"""Guard process bookkeeping and safe filtering at RootHide launchd boundaries."""
from pathlib import Path
import unittest

SRC = (Path(__file__).resolve().parents[2] /
       "BaseBin/launchdhook/src/spawn_hook.c")


class RootHideSpawnVisibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SRC.read_text(encoding="utf-8")

    def test_successful_launchd_children_registered_by_uniqueid(self):
        source = self.text
        section = source[source.index("int __posix_spawn_orig_wrapper"):
                         source.index("static bool roothide_blacklisted_uikit_proxy")]
        self.assertIn("pid ? pid : &localPid", section)
        self.assertIn("__posix_spawn_inline(recordedPid", section)
        self.assertIn("r == 0 && *recordedPid > 0 && roothide_is_active()", section)
        self.assertIn("register_job(*recordedPid)", section)

    def test_xpcproxy_uikit_labels_are_checked_as_app_identifiers(self):
        source = self.text
        section = source[source.index("static bool roothide_blacklisted_uikit_proxy"):
                         source.index("int __posix_spawn_hook(", source.index("static bool roothide_blacklisted_uikit_proxy"))]
        self.assertIn('strcmp(path, "/usr/libexec/xpcproxy") != 0', section)
        self.assertIn('"UIKitApplication:"', section)
        self.assertIn("strchr(identifier, '[')", section)
        self.assertIn("length >= 256", section)
        self.assertIn("isBlacklistedApp(bundleId)", section)
        self.assertIn("roothide_blacklisted_uikit_proxy(path, argv)", source)
        self.assertIn("roothide_spawn_uninjected(trackedPid", source)


if __name__ == "__main__":
    unittest.main()
