"""r156 guards for bounded SSH and mobile-account diagnostics on existing installs."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
ENV = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(encoding="utf-8")


class R156RuntimeChecks(unittest.TestCase):
    def test_ssh_preserves_donor_root_wheel_library_only(self):
        section = ENV.split("- (int)repairRootHideSSH", 1)[1].split(
            "- (int)verifyRootHideTweakInjection", 1
        )[0]
        self.assertIn('trustedLibrary = [suffix isEqualToString:@"Library"]', section)
        self.assertIn('st.st_gid == 0 && (st.st_mode & 0777) == 0775', section)
        self.assertIn('(st.st_mode & S_IWOTH)', section)
        self.assertIn('st.st_uid != 0 || unsafeMode', section)
        self.assertIn('O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC', section)
        self.assertIn('SSH preflight: directory %@ is not safely owned', section)
        self.assertIn('SSH preflight: existing ED25519 host key rejected', section)
        self.assertNotIn('chmod(', section)
        self.assertNotIn('chown(', section)

    def test_password_failed_command_never_assumed_atomic(self):
        section = ENV.split("- (int)changeMobilePassword:", 1)[1].split(
            "- (NSError*)updateEnvironment", 1
        )[0]
        self.assertIn('mobile password preflight: master_safe=', section)
        self.assertIn('pwd_mkdb_executable=%d', section)
        self.assertIn('mobile password failed-command verification:', section)
        self.assertIn('no automatic retry', section)
        self.assertIn('![after isEqualToString:before]', section)
        self.assertNotIn('sendLog:newPassword', section)
        self.assertIn('rh3RunCommand:JBROOT_PATH(@"/usr/sbin/pw")', section)


if __name__ == "__main__":
    unittest.main()
