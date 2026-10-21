"""Regression safeguards for the opt-in, read-only NewTerm diagnostic.

The on-disk UUID must be obtained from the installed executable, not from a
crash log of a pre-upgrade process renamed *.dpkg-tmp by dpkg.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(
    encoding="utf-8"
)


class RootHideNewTermRuntimeDiagnosticsTests(unittest.TestCase):
    def test_macho_uuid_reader_is_bounded_and_never_executes_image(self):
        reader = SOURCE.split("static NSString *RH3MachOUUIDForExecutable", 1)[1].split(
            "@implementation DOEnvironmentManager", 1
        )[0]
        for required in (
            "O_RDONLY | O_CLOEXEC | O_NOFOLLOW",
            "S_ISREG(info.st_mode)",
            "header.magic != MH_MAGIC_64",
            "header.ncmds > 4096",
            "header.sizeofcmds > 65536",
            "pread(fd, &header",
            "pread(fd, commands",
            "command.cmd == LC_UUID",
            "uuid_unparse_lower",
        ):
            with self.subTest(required=required):
                self.assertIn(required, reader)
        for forbidden in ("posix_spawn", "execve(", "system(", "dlopen("):
            self.assertNotIn(forbidden, reader)

    def test_runtime_probe_stays_inside_verified_hidden_root(self):
        probe = SOURCE.split("- (int)diagnoseRootHideRuntime", 1)[1].split(
            "- (int)repairRootHideSSH", 1
        )[0]
        self.assertIn("rootHideExistingRootWithError", probe)
        self.assertIn("jbclient_get_jbroot()", probe)
        self.assertIn('stringByAppendingPathComponent:@"Applications/NewTerm.app"', probe)
        self.assertIn('isEqual:@"ws.hbang.Terminal"', probe)
        self.assertIn('stringByAppendingPathComponent:@"usr/bin/login"', probe)
        self.assertIn("newterm_macho_uuid=%@", probe)
        self.assertIn("newTermExecutablePresent", probe)
        self.assertIn("newTermHelperPresent", probe)
        self.assertIn("loginPresent", probe)


if __name__ == "__main__":
    unittest.main()
