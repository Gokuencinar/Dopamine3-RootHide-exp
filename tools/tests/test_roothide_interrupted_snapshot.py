"""Protect read-only reporting of an interrupted RootHide setup transaction.

These static checks do not establish on-device process state or safe recovery.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(encoding="utf-8")


class InterruptedSnapshotContract(unittest.TestCase):
    def test_diagnostics_use_only_lstat_metadata_not_password_contents(self):
        snapshot = SOURCE.split('static NSString *RH3RecoveryPathKind(', 1)[1].split(
            '// The pinned RootHide donor archive contains', 1)[0]
        self.assertIn('lstat(path.fileSystemRepresentation, &st)', snapshot)
        self.assertIn('symlink (not followed)', snapshot)
        self.assertIn('RECOVERY result: indeterminate', snapshot)
        self.assertIn('RECOVERY read-only snapshot: running-script', snapshot)
        self.assertIn('@"etc/master.passwd"', snapshot)
        self.assertIn('@".installing_roothide3"', snapshot)
        for destructive in ('unlink(', 'removeItemAtPath:', 'moveItemAtPath:',
                            'RH3WritePendingState(', 'exec_cmd(', 'posix_spawn(',
                            'stringWithContentsOfFile:', 'dataWithContentsOfFile:'):
            self.assertNotIn(destructive, snapshot)

    def test_snapshot_only_on_owned_running_script_state(self):
        lookup = SOURCE.split('- (NSError *)rootHidePreflightError\n{', 1)[1].split(
            '- (NSError *)rh3BuildPackageSourcesInRoot:', 1)[0]
        prepare = SOURCE.split('- (void)prepareRootHideBootstrapWithCompletion:', 2)[-1].split(
            '- (NSError *)finalizeRootHideBootstrap\n{', 1)[0]
        finalize = SOURCE.split('- (NSError *)finalizeRootHideBootstrap\n{', 1)[1].split(
            '- (NSError *)deleteRootHideBootstrap\n{', 1)[0]
        self.assertIn('rootHideExistingRootWithError:&error', lookup)
        self.assertIn('if ([stage isEqualToString:@"running-script"]) {\n                RH3LogInterruptedBootstrapSnapshot(root);', lookup)
        self.assertIn('if (!recovery) return RH3LegacyRecoveryEligibility(root);', lookup)
        self.assertIn('if ([stage isEqualToString:@"running-script"])\n                RH3LogInterruptedBootstrapSnapshot(root);', prepare)
        self.assertIn('if ([pending isEqualToString:@"running-script"]) {\n        RH3LogInterruptedBootstrapSnapshot(root);', finalize)
        self.assertIn('Export the RootHide diagnostic log; the existing bootstrap and marker were preserved.', prepare)
        self.assertLess(prepare.index('RH3LogInterruptedBootstrapSnapshot(root);'),
                        prepare.index('[self rh3InstallBasebinAtRoot:root]'))


if __name__ == '__main__':
    unittest.main()
