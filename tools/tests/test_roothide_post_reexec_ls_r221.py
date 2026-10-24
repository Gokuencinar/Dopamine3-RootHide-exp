"""Post-reexec LaunchServices evidence without changing installed apps.

The host can compile the production classification header, but cannot query
an iPhone's current lsd database. These tests protect diagnostic semantics
and the separation of the explicit refresh button from read-only reporting.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAPPER = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text()
BOOTSTRAPPER_H = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.h").read_text()
SETTINGS = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m").read_text()
STATUS = ROOT / "Application/Dopamine/Jailbreak/RootHideLSRecordStatus.h"


class PostReexecLSClassificationTests(unittest.TestCase):
    def test_native_classification_distinguishes_nil_url_wrong_root_and_match(self):
        compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not compiler:
            self.skipTest("No host C compiler")
        fixture = r'''
#include "RootHideLSRecordStatus.h"
int main(void) {
    if (RH3ClassifyLSRecord(false,false,false,false,false)!=RH3LSProxyNil) return 1;
    if (RH3ClassifyLSRecord(true,false,false,false,true)!=RH3LSBundleURLMissing) return 2;
    if (RH3ClassifyLSRecord(true,true,false,false,true)!=RH3LSExpectedRootUnknown) return 3;
    if (RH3ClassifyLSRecord(true,true,true,false,true)!=RH3LSWrongRoot) return 4;
    if (RH3ClassifyLSRecord(true,true,true,true,false)!=RH3LSProxyNotInstalled) return 5;
    if (RH3ClassifyLSRecord(true,true,true,true,true)!=RH3LSRegisteredCurrentRoot) return 6;
    if (__builtin_strcmp(RH3LSRecordStatusName(RH3LSProxyNil),"proxy_nil")) return 7;
    if (__builtin_strcmp(RH3LSRecordStatusName(RH3LSBundleURLMissing),"bundleURL_missing")) return 8;
    if (__builtin_strcmp(RH3LSRecordStatusName(RH3LSWrongRoot),"wrong_root")) return 9;
    if (__builtin_strcmp(RH3LSRecordStatusName(RH3LSRegisteredCurrentRoot),"registered_current_root")) return 10;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory) / "test_record.c"
            exe = Path(directory) / "test_record.exe"
            src.write_text(fixture, encoding="utf-8")
            build = subprocess.run(
                [compiler, "-std=c11", "-Werror", "-Wall", "-Wextra",
                 "-I", str(STATUS.parent), str(src), "-o", str(exe)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_snapshot_queries_fresh_server_root_not_dispatch_once_cache(self):
        scope = BOOTSTRAPPER.split(
            "+ (void)recordRootHideLaunchServicesSnapshotWithContext:", 1
        )[1].split("static int RH3ExplicitRefreshLSStateDecision(", 1)[0]
        self.assertIn("JBS_DOMAIN_SYSTEMWIDE", scope)
        self.assertIn("JBS_SYSTEMWIDE_GET_JBROOT", scope)
        self.assertIn('xpc_dictionary_get_string(rootReply, "root-path")', scope)
        self.assertNotIn("jbclient_get_jbroot()", scope.replace(
            "// Do NOT use jbclient_get_jbroot():", ""))
        self.assertIn("app_root_matches_server", scope)
        self.assertIn("rootHideBrandForPath:canonicalServerRoot", scope)
        self.assertIn("RH3CanonicalAppPath(serverRoot)", scope)
        self.assertIn("RH3ClassifyLSRecord", scope)
        self.assertIn("RH3StaleRegisteredRoot(registered, expected)", scope)
        self.assertIn("LSApplicationProxy applicationProxyForIdentifier:app[1]", scope)
        self.assertIn("bundleURL_missing", STATUS.read_text())
        self.assertIn("+ (void)recordRootHideLaunchServicesSnapshotWithContext:", BOOTSTRAPPER_H)
        for forbidden in ("exec_cmd", "execve", "posix_spawn", "uicache -p", "uicache\")",
                          "installPackage", "dpkg", "trust_file", "jb_trustcache", "rebootUserspace"):
            # Comments about forbidden operations are allowed; no invocation.
            self.assertNotIn(f"[{forbidden}", scope)
        self.assertNotIn("dispatch_group_async", scope)

    def test_report_is_read_only_and_after_privilege_drop(self):
        report = SETTINGS.split("- (void)diagnoseRootHideAllPressed", 1)[1].split(
            "- (void)diagnoseRootHideRuntimePressed", 1
        )[0]
        self.assertLess(
            report.index("diagnoseRootHideComprehensive]"),
            report.index('recordRootHideLaunchServicesSnapshotWithContext:@"full-diagnostic"'),
        )
        self.assertLess(
            report.index('recordRootHideLaunchServicesSnapshotWithContext:@"full-diagnostic"'),
            report.index("rh3FinishUnifiedReportWithResult:result]"),
        )
        self.assertNotIn("refreshJailbreakApps]", report)

    def test_explicit_refresh_is_only_postboot_registration_path(self):
        refresh = SETTINGS.split("- (void)refreshJailbreakAppsPressed", 1)[1].split(
            "- (void)repairRootHideLibkrwPressed", 1
        )[0]
        self.assertEqual(refresh.count("refreshJailbreakApps]"), 2)  # RootHide and stock paths
        self.assertIn('if (result != ETIMEDOUT) {\n'
                      '                    [DOBootstrapper recordRootHideLaunchServicesSnapshotWithContext:@"after-explicit-refresh"]',
                      refresh)
        self.assertLess(
            refresh.index("refreshJailbreakApps]"),
            refresh.index('recordRootHideLaunchServicesSnapshotWithContext:@"after-explicit-refresh"'),
        )
        self.assertIn("gRootHideAppsRefreshInFlight", refresh)


if __name__ == "__main__":
    unittest.main()
