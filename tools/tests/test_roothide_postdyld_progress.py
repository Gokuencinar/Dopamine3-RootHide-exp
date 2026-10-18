"""Source contracts for the iOS16 RootHide post-dyld bootstrap hang.

These protect the target path; only hardware logs can prove the stall fixed.
"""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
JAILBREAKER = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text(encoding="utf-8")
BOOTSTRAPPER = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(encoding="utf-8")


class RootHidePostDyldProgress(unittest.TestCase):
    def test_nonessential_iconservicesagent_refresh_skipped_only_for_roothide(self):
        # Previously the call was unconditional and a hung child patch IPC
        # could strand the UI before the first bootstrap checkpoint.
        boundary = JAILBREAKER.split('phase: dyld generation complete', 1)[1]
        boundary = boundary.split('*errOut = [self finalizeBootstrapIfNeeded]', 1)[0]
        self.assertIn('phase: RootHide helper environment configured', boundary)
        self.assertIn('phase: deferring optional iconservicesagent refresh', boundary)
        self.assertIn('exec_cmd_trusted(JBROOT_PATH("/usr/bin/killall"), "-9", "iconservicesagent", NULL);', boundary)
        self.assertIn('if ([DOBootstrapper rootHidePortEnabled]) {', boundary)
        self.assertIn('else {\n        exec_cmd_trusted(JBROOT_PATH("/usr/bin/killall")', boundary)
        self.assertLess(boundary.index('phase: deferring optional iconservicesagent refresh'),
                        boundary.index('phase: starting RootHide bootstrap finalization'))

    def test_root_hide_finalization_has_persistent_helper_checkpoints(self):
        scope = BOOTSTRAPPER.split('- (NSError *)finalizeRootHideBootstrap\n{', 1)[1]
        scope = scope.split('- (NSError *)deleteRootHideBootstrap\n{', 1)[0]
        checkpoints = [
            'bootstrap: validation starting',
            'bootstrap: running-script marker saved; spawning prep_bootstrap.sh',
            'bootstrap: prep_bootstrap.sh returned %d',
            'bootstrap: installing RootHide dependencies',
            'bootstrap: RootHide dependencies installed',
            'bootstrap: installing package managers',
            'bootstrap: RootHide Manager dpkg exited %d',
            'bootstrap: RootHide finalization committed',
        ]
        for name in checkpoints:
            with self.subTest(stage=name):
                self.assertIn(name, scope)
        self.assertLess(scope.index('RH3WritePendingState(root, @"running-script")'),
                        scope.index('exec_cmd_env_nowait(&scriptPid, scriptEnvironment'))
        self.assertIn('RootHide setup script execution was interrupted; manual recovery required', scope)


if __name__ == '__main__':
    unittest.main()
