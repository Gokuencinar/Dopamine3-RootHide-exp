"""Security and partial-result contracts for the RootHide one-tap report.

This is static host verification; no iPhone runtime is simulated.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
UI = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m")
ENV = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m")
MANAGER = (ROOT / "Application/Dopamine/UI/DOUIManager.m")
REPORT = (ROOT / "Application/Dopamine/UI/RH3DiagnosticFile.h")
SERVER = (ROOT / "BaseBin/jailbreakd/src/server.m")


class UnifiedSafetyTests(unittest.TestCase):
    def test_one_button_accessible_after_jailbreak_failed(self):
        source = UI.read_text(encoding="utf-8")
        settings = source.split("if ([DOBootstrapper rootHidePortEnabled]) {", 1)[1].split(
            "if (envManager.isBootstrapped) {", 1)[0]
        self.assertIn('@"diagnoseRootHideAllPressed"', settings)
        self.assertEqual(source.count("[specifiers addObject:diagnoseAll]"), 1)

    def test_snapshot_is_not_old_boot_log_and_can_close_partial(self):
        ui = UI.read_text(encoding="utf-8").split("- (void)diagnoseRootHideAllPressed", 1)[1]
        ui = ui.split("- (void)diagnoseRootHideRuntimePressed", 1)[0]
        manager = MANAGER.read_text(encoding="utf-8")
        report = REPORT.read_text(encoding="utf-8")
        for token in ("rh3BeginUnifiedReport", "rh3FinishUnifiedReportWithResult:",
                      "ETIMEDOUT", "dispatch_after", "partialShared", "finished",
                      "gRootHideFullDiagnosisInFlight"):
            self.assertIn(token, ui)
        self.assertNotIn("rh3PreviousDiagnosticURL", ui)
        self.assertIn("RH3UnifiedReportLimit = 384 * 1024", report)
        self.assertIn("RH3CreateUnifiedReport", report)
        self.assertIn("RH3AppendBootHistoryToReport", report)
        self.assertIn("O_NOFOLLOW | O_CLOEXEC", report)
        self.assertIn("O_EXCL | O_APPEND", report)
        self.assertIn("RH3 UNIFIED BEGIN", manager)
        self.assertIn("RH3 UNIFIED END", manager)
        self.assertIn("report_write_error", manager)
        self.assertIn("fsync(fd)", report)

    def test_full_diagnosis_does_not_trigger_patch_or_trustcache(self):
        source = ENV.read_text(encoding="utf-8")
        start = source.index("- (int)diagnoseRootHideComprehensive")
        end = source.index("// Explicit, opt-in repair", start)
        body = source[start:end]
        for forbidden in ("[self verifyRootHideTweakInjection]", "jbclient_trust_library_recurse",
                          "jbclient_trust_executable_recurse", "kill(", "ssh-keygen",
                          "kickstart", "reboot_np(", "repairRootHideSSH",
                          "refreshJailbreakApps"):
            self.assertNotIn(forbidden, body)
        self.assertIn("no trustcache edits or child patching", body)
        self.assertIn("tweak_load_proof=not_measured", body)
        self.assertIn("ssh_banner=not_measured", body)
        self.assertIn('@"private_dyld", @"basebin/.fakelib/dyld"', body)

    def test_probe_patch_result_is_not_misreported_as_dyld(self):
        source = SERVER.read_text(encoding="utf-8")
        part = source.split("case JBD_MSG_SPAWN_PATCH_CHILD:", 1)[1].split(
            "case JBD_MSG_SPAWN_EXEC_START:", 1)[0]
        self.assertIn('string_has_suffix(childPath, "/basebin/rh3tweakprobe")', part)
        self.assertIn("dyld_patch_enabled()", part)
        self.assertIn("not_constructor_proof", part)
        self.assertNotIn("dyld mapped successfully", part)

    def test_arc_report_path_writeback_uses_local_strong_variable(self):
        """Regression for r182 Xcode CompileC DOUIManager.m:331 ARC failure."""
        source = MANAGER.read_text(encoding="utf-8")
        begin = source.split("- (BOOL)rh3BeginUnifiedReport", 1)[1].split(
            "- (NSURL *)rh3FinishUnifiedReportWithResult", 1)[0]
        self.assertNotIn("&_rh3UnifiedReportPath", begin)
        self.assertIn("NSString *createdPath = nil;", begin)
        self.assertIn("RH3CreateUnifiedReport(_rh3DiagnosticDirectory, &createdPath)", begin)
        self.assertIn("_rh3UnifiedReportPath = createdPath;", begin)


if __name__ == "__main__":
    unittest.main()
