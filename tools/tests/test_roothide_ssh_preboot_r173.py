"""r173 OpenSSH write-path regressions; native iOS/APFS remains untested.

The source checks guard the production Objective-C transaction. Where the host
supports openat/O_NOFOLLOW, the negative cases also exercise OS path semantics.
"""

import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(
    encoding="utf-8"
)
TRANSACTION = SOURCE.split("static int RH3SSHRebaseInstalledPlist(", 1)[1].split(
    "// Procursus names the entries", 1
)[0]
REPAIR = SOURCE.split("- (int)rh3RepairRootHideSSHAllowKeyGeneration:", 1)[1].split(
    "- (int)prepareRootHideOpenSSHBeforeUserspaceReboot", 1
)[0]
PREBOOT = SOURCE.split("- (int)prepareRootHideOpenSSHBeforeUserspaceReboot", 1)[1].split(
    "// Read the effective launchd disabled override", 1
)[0]


class RootHideSSHPrebootR173(unittest.TestCase):
    def test_only_exact_openssh_job_under_library_daemons_can_be_rebased(self):
        self.assertIn('isEqualToString:@"com.openssh.sshd.plist"', TRANSACTION)
        self.assertIn('isEqualToString:@"LaunchDaemons"', TRANSACTION)
        self.assertIn('isEqualToString:@"Library"', TRANSACTION)
        self.assertIn('return ENOTSUP;', TRANSACTION)
        self.assertLess(TRANSACTION.index('isEqualToString:@"Library"'),
                        TRANSACTION.index('open(libraryDirectory.fileSystemRepresentation'))

    def test_parent_pinned_without_following_symlink_or_group_writable_foreign_dir(self):
        self.assertIn('open(libraryDirectory.fileSystemRepresentation,', TRANSACTION)
        self.assertIn('O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC', TRANSACTION)
        self.assertIn('fstat(libraryFD, &libraryInfo)', TRANSACTION)
        self.assertIn('libraryInfo.st_uid != 0', TRANSACTION)
        self.assertIn('libraryInfo.st_gid == 0', TRANSACTION)
        self.assertIn('(libraryInfo.st_mode & 0777) == 0775', TRANSACTION)
        self.assertIn('(libraryInfo.st_mode & S_IWOTH)', TRANSACTION)
        self.assertIn('((libraryInfo.st_mode & S_IWGRP) && !trustedLibrary)', TRANSACTION)
        self.assertIn('openat(libraryFD, "LaunchDaemons",', TRANSACTION)
        self.assertIn('if (directoryError) return directoryError;', TRANSACTION)
        self.assertLess(TRANSACTION.index('if (libraryError) {'),
                        TRANSACTION.index('openat(libraryFD, "LaunchDaemons"'))
        self.assertLess(TRANSACTION.index('openat(libraryFD, "LaunchDaemons"'),
                        TRANSACTION.index('openat(dir, jobName,'))
        self.assertNotIn('open(plistPath.stringByDeletingLastPathComponent.fileSystemRepresentation',
                         TRANSACTION)

    def test_error_exits_preserve_files_and_report_bounded_stage(self):
        self.assertIn('if (stageOut) *stageOut = "open_library";', TRANSACTION)
        self.assertIn('if (stageOut) *stageOut = "library_stat";', TRANSACTION)
        self.assertIn('if (stageOut) *stageOut = "open_directory";', TRANSACTION)
        self.assertIn('close(libraryFD);\n        return libraryError;', TRANSACTION)
        self.assertIn('int directoryError = dir < 0 ? errno : 0;', TRANSACTION)
        self.assertIn('close(libraryFD);\n    if (directoryError) return directoryError;',
                      TRANSACTION)
        self.assertLess(TRANSACTION.index('if (directoryError) return directoryError;'),
                        TRANSACTION.index('stage = "open_original";'))
        self.assertIn('linkat(dir, jobName, dir, rollbackName, 0)', TRANSACTION)
        self.assertIn('renameat(dir, rollbackName, dir, jobName)', TRANSACTION)
        self.assertIn('if (changed) *changed = NO;', TRANSACTION)

    def test_ssh_consent_and_installer_phase_still_fail_closed(self):
        self.assertIn('@"rh3SSHInstallerRepairOptIn" fallback:ROOTHIDE3_SSH_DEFAULT_PREPARE', PREBOOT)
        self.assertIn('!(flags & CS_INSTALLER)', PREBOOT)
        self.assertIn('!(flags & CS_PLATFORM_BINARY)', PREBOOT)
        self.assertIn('rh3RepairRootHideSSHAllowKeyGeneration:NO installerPhase:YES', PREBOOT)
        self.assertIn('if (needsKey && !allowKeyGeneration)', REPAIR)
        self.assertIn('installerPhase ? sshPreflight() :', REPAIR)
        self.assertIn('installerPhase ? sshCommit() :', REPAIR)
        self.assertIn('if (!installerPhase) {', REPAIR)
        self.assertNotIn('proc_csflags_set', PREBOOT + REPAIR)
        self.assertNotIn('launchctl bootstrap', PREBOOT + REPAIR)

    @unittest.skipUnless(all(hasattr(os, field) for field in
                              ('O_DIRECTORY', 'O_NOFOLLOW', 'supports_dir_fd')) and
                         os.open in os.supports_dir_fd,
                         'POSIX openat with O_NOFOLLOW is unavailable')
    def test_posix_negative_parent_and_child_symlinks_rejected(self):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            valid = root / 'real-Library'
            (valid / 'LaunchDaemons').mkdir(parents=True)
            (root / 'Library').symlink_to(valid, target_is_directory=True)
            with self.assertRaises(OSError):
                os.open(root / 'Library', flags)

            parent_fd = os.open(valid, flags)
            try:
                daemon_fd = os.open('LaunchDaemons', flags, dir_fd=parent_fd)
                os.close(daemon_fd)
                (valid / 'LaunchDaemons').rename(valid / 'previous-daemons')
                (valid / 'LaunchDaemons').symlink_to(root, target_is_directory=True)
                with self.assertRaises(OSError):
                    os.open('LaunchDaemons', flags, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)


if __name__ == '__main__':
    unittest.main()
