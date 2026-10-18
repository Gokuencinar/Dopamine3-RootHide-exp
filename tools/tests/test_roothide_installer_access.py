"""Regressions for the missing RootHide2 installer step before mkdir(.jbroot)."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InstallerAccessTests(unittest.TestCase):
    def test_root_access_is_not_equated_with_installer_access(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text(encoding="utf-8")
        elevation = source.split("- (NSError *)elevatePrivileges\n{", 1)[1].split("- (NSError *)showNonDefaultSystemApps", 1)[0]
        guard = elevation.split("if ([DOBootstrapper rootHidePortEnabled]) {", 1)[1]
        self.assertIn("proc_csflags_set(proc, CS_INSTALLER);", guard)
        self.assertLess(guard.index("proc_csflags_set(proc, CS_INSTALLER)"), guard.index("csops(getpid()"))
        self.assertIn("status != 0 || !(csflags & CS_INSTALLER)", guard)
        self.assertIn("RootHide installer access could not be enabled", guard)
        # No directory flags, global policy or donor namecache layouts are changed.
        self.assertNotIn("chflags", elevation)
        self.assertNotIn("chmod", elevation)
        self.assertNotIn("unsandbox1(", elevation)
        entry = source.split("- (void)runWithError:", 1)[1]
        self.assertLess(entry.index("[self elevatePrivileges]"), entry.index("ensureJailbreakRootExists"))
        self.assertLess(entry.index("[self elevatePrivileges]"), entry.index("prepareBootstrap"))

