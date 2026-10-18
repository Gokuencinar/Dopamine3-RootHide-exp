"""Source-level contracts for crash-surviving RootHide diagnostic checkpoints.

These assertions do not reproduce a live launchd panic or prove the jailbreak.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
UI = (ROOT / "Application/Dopamine/UI/DOUIManager.m").read_text(encoding="utf-8")
MAIN = (ROOT / "Application/Dopamine/UI/DOMainViewController.m").read_text(encoding="utf-8")
JAILBREAKER = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text(encoding="utf-8")
STUB_H = (ROOT / "BaseBin/dopamine/src/ui-stub/DOUIManager.h").read_text(encoding="utf-8")
STUB_M = (ROOT / "BaseBin/dopamine/src/ui-stub/DOUIManager.m").read_text(encoding="utf-8")
FILE = (ROOT / "Application/Dopamine/UI/RH3DiagnosticFile.h").read_text(encoding="utf-8")
SCENE = (ROOT / "Application/Dopamine/App Delegates/DOSceneDelegate.m").read_text(encoding="utf-8")


class RootHidePersistentDiagnostics(unittest.TestCase):
    def test_diagnostics_live_in_original_sandbox_and_sync_each_checkpoint(self):
        self.assertIn('@"RootHide3-last-attempt.log"', FILE)
        self.assertIn('NSHomeDirectory()', UI)
        self.assertIn('#if RH3_FULL_APP_EXPERIMENTAL', UI)
        self.assertIn('O_NOFOLLOW', FILE)
        self.assertIn('O_CLOEXEC', FILE)
        self.assertIn('O_EXCL', FILE)
        self.assertNotIn('O_TRUNC', FILE)
        self.assertIn('O_APPEND', FILE)
        self.assertIn('S_ISREG(st.st_mode)', FILE)
        self.assertIn('RH3DiagnosticLimit = 128 * 1024', FILE)
        self.assertIn('return fsync(fd) == 0 ? 0 : errno;', FILE)
        self.assertIn('RH3AppendDiagnostic(_rh3DiagnosticFD', UI)
        writer = UI.split('- (void)rh3WriteDiagnosticLine:', 1)[1].split('- (BOOL)rh3BeginDiagnosticAttempt', 1)[0]
        self.assertNotIn('open(', writer)
        self.assertNotIn('close(', writer)
        self.assertIn('rh3BeginDiagnosticAttempt', UI)
        self.assertIn('rh3PreviousDiagnosticURL', UI)
        self.assertIn('return nil;', UI)

    def test_failed_log_start_prevents_exploitation_and_export_has_no_ipc(self):
        self.assertIn('if (![[DOUIManager sharedInstance] rh3BeginDiagnosticAttempt])', JAILBREAKER)
        self.assertIn('No exploit was started.', JAILBREAKER)
        self.assertLess(JAILBREAKER.index('if (![[DOUIManager sharedInstance] rh3BeginDiagnosticAttempt])'),
                        JAILBREAKER.index('*errOut = [self doExploitation]'))
        landing = SCENE.split('#if RH3_FULL_APP_EXPERIMENTAL', 1)[1].split('#else', 1)[0]
        self.assertIn('window.rootViewController = landing;', landing)
        self.assertIn('RH3LatestDiagnosticURL(directory)', landing)
        self.assertIn('Compartir último diagnóstico', landing)
        self.assertNotIn('[DOEnvironmentManager', landing)
        self.assertNotIn('jbclient_', landing)
        self.assertIn('@"END FAILED: %@"', MAIN)

    def test_injection_hardware_crash_is_distinguishable_from_successful_reboot(self):
        self.assertIn('@"phase: about to inject hook into PID 1 (crash-sensitive)"', JAILBREAKER)
        self.assertIn('@"launchd: jbctl stash-port succeeded"', JAILBREAKER)
        self.assertIn('@"launchd: opainject spawn about to start"', JAILBREAKER)
        self.assertIn('@"launchd: opainject exited 0"', JAILBREAKER)
        self.assertIn('@"launchd: boomerang handshake completed"', JAILBREAKER)
        self.assertIn('@"phase: bootstrap finalization completed"', JAILBREAKER)
        self.assertIn('@"phase: requesting intentional userspace reboot"', JAILBREAKER)
        self.assertLess(
            JAILBREAKER.index('@"phase: about to inject hook into PID 1'),
            JAILBREAKER.index('*errOut = [self injectLaunchdHook]')
        )
        self.assertLess(
            JAILBREAKER.index('@"phase: starting RootHide bootstrap finalization'),
            JAILBREAKER.index('*errOut = [self finalizeBootstrapIfNeeded]')
        )

    def test_previous_log_can_be_shared_without_jailbreak(self):
        self.assertIn('identifier:@"rh3-share-previous-log"', MAIN)
        self.assertIn('rh3PreviousDiagnosticURL', MAIN)
        self.assertIn('UIActivityViewController', MAIN)
        self.assertIn('initWithActivityItems:@[logURL]', MAIN)
        self.assertIn('#if RH3_FULL_APP_EXPERIMENTAL', MAIN)
        self.assertIn('No log has been recorded by this build', MAIN)

    def test_standalone_cli_ui_stub_exposes_inert_diagnostic_methods(self):
        # The BaseBin/dopamine build compiles DOJailbreaker.m against this
        # independent stub, not the application's DOUIManager.h/.m.
        for selector in ('rh3BeginDiagnosticAttempt', 'rh3RecordDiagnosticStage:', 'rh3PreviousDiagnosticURL'):
            self.assertIn(selector, STUB_H)
            self.assertIn(selector, STUB_M)
        self.assertIn('(void)stage;', STUB_M)
        self.assertIn('return nil;', STUB_M)
        self.assertNotIn('RootHide3-last-attempt.log', STUB_M)
        self.assertNotIn('fsync(', STUB_M)


if __name__ == "__main__":
    unittest.main()
