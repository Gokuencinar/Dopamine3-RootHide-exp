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


class RootHidePersistentDiagnostics(unittest.TestCase):
    def test_diagnostics_live_in_original_sandbox_and_sync_each_checkpoint(self):
        self.assertIn('@"Documents/RootHide3-last-attempt.log"', UI)
        self.assertIn('NSHomeDirectory()', UI)
        self.assertIn('#if RH3_FULL_APP_EXPERIMENTAL', UI)
        self.assertIn('O_NOFOLLOW', UI)
        self.assertIn('O_CLOEXEC', UI)
        self.assertIn('O_TRUNC', UI)
        self.assertIn('O_APPEND', UI)
        self.assertIn('S_ISREG(st.st_mode)', UI)
        self.assertIn('st.st_size <= 65536', UI)
        self.assertIn('(void)fsync(fd);', UI)
        self.assertIn('rh3BeginDiagnosticAttempt', UI)
        self.assertIn('rh3PreviousDiagnosticURL', UI)
        self.assertIn('return nil;', UI)

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
