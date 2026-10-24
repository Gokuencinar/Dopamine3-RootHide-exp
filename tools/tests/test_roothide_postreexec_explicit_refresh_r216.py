"""r216: post-reexec LS placeholders require truthful, explicitly gated repair.

Real hardware: Sileo/Zebra/RootHide each has proxy=1, bundleURL=0,
installed=0 after userspace reboot, even though installer uicache -p exited 0.
No physical post-reexec manual-refresh result was supplied.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BOOT = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text()
HEADER = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.h").read_text()
UI = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m").read_text()


class ExplicitPostreexecRegistrationTests(unittest.TestCase):
    def test_native_preflight_decision_never_overwrites_foreign_record(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("C compiler unavailable")
        native = BOOT.split("static int RH3ExplicitRefreshLSStateDecision(", 1)[1].split(
            "static int RH3ExplicitRefreshLSCheck(", 1)[0]
        native = "static int RH3ExplicitRefreshLSStateDecision(" + native
        fixture = """
#include <errno.h>
#include <stdbool.h>
#include "RootHideLSRecordStatus.h"
typedef bool BOOL;
""" + native + """
int main(void) {
    if (RH3ExplicitRefreshLSStateDecision(RH3LSProxyNil, false)!=EAGAIN) return 1;
    if (RH3ExplicitRefreshLSStateDecision(RH3LSBundleURLMissing, false)!=EAGAIN) return 2;
    if (RH3ExplicitRefreshLSStateDecision(RH3LSBundleURLMissing, true)!=EEXIST) return 3;
    if (RH3ExplicitRefreshLSStateDecision(RH3LSWrongRoot, true)!=EEXIST) return 4;
    if (RH3ExplicitRefreshLSStateDecision(RH3LSWrongRoot, false)!=EEXIST) return 5;
    if (RH3ExplicitRefreshLSStateDecision(RH3LSExpectedRootUnknown, false)!=EEXIST) return 6;
    if (RH3ExplicitRefreshLSStateDecision(RH3LSProxyNotInstalled, false)!=EAGAIN) return 7;
    if (RH3ExplicitRefreshLSStateDecision(RH3LSRegisteredCurrentRoot, true)!=0) return 8;
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory) / "decision.c"
            exe = Path(directory) / "decision.exe"
            src.write_text(fixture)
            result = subprocess.run(
                [cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-I", str(ROOT / "Application/Dopamine/Jailbreak"),
                 str(src), "-o", str(exe)], capture_output=True, text=True, timeout=30
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_only_pinned_bundle_ids_and_fresh_root(self):
        check = BOOT.split("static int RH3ExplicitRefreshLSCheck(", 1)[1].split(
            "+ (int)preflightExplicitRootHideAppRefresh", 1
        )[0]
        for literal in ('org.coolstar.SileoStore', 'xyz.willy.Zebra', 'com.roothide.manager'):
            self.assertIn(literal, check)
        self.assertIn("JBS_DOMAIN_SYSTEMWIDE", check)
        self.assertIn("JBS_SYSTEMWIDE_GET_JBROOT", check)
        self.assertNotIn("jbclient_get_jbroot()", check)
        self.assertIn("rootHideBrandForPath:root", check)
        self.assertIn("RH3ExplicitRefreshLSStateDecision", check)
        self.assertIn("return EEXIST;", check)
        self.assertIn("return incomplete ? EAGAIN : 0;", check)
        self.assertIn("return complete == apps.count ? EALREADY : 0;", check)
        for forbidden in ("-u", "unregisterApplication", "installPackage", "dpkg",
                          "killall", "posix_spawn", "exec_cmd", "rebootUserspace"):
            self.assertNotIn(forbidden, check)

    def test_readonly_timeout_and_passive_verification_three_checks(self):
        scope = BOOT.split("+ (int)preflightExplicitRootHideAppRefresh", 1)[1].split(
            "- (NSError *)repairRootHideAppLinks", 1
        )[0]
        self.assertIn("RH3AwaitExplicitLSCheck", scope)
        self.assertIn("4 * NSEC_PER_SEC", BOOT)
        self.assertIn("return finished ? result : ETIMEDOUT;", scope)
        self.assertIn("for (unsigned check = 0; check < 3; check++)", scope)
        self.assertIn("usleep(250000)", scope)
        self.assertNotIn("exec_cmd(", scope)
        self.assertNotIn("posix_spawn(", scope)
        self.assertNotIn("kill(", scope)
        self.assertIn("+ (int)preflightExplicitRootHideAppRefresh", HEADER)
        self.assertIn("+ (int)verifyExplicitRootHideAppRefresh", HEADER)

    def test_ui_uses_single_existing_command_and_verifies_all_three_apps(self):
        refresh = UI.split("- (void)refreshJailbreakAppsPressed", 1)[1].split(
            "- (void)repairRootHideLibkrwPressed", 1
        )[0]
        self.assertEqual(refresh.count("[[DOEnvironmentManager sharedManager] refreshJailbreakApps]"), 2)
        first = refresh.index("[DOBootstrapper preflightExplicitRootHideAppRefresh]")
        command = refresh.index("[[DOEnvironmentManager sharedManager] refreshJailbreakApps]")
        verify = refresh.index("[DOBootstrapper verifyExplicitRootHideAppRefresh]")
        self.assertLess(first, command)
        self.assertLess(command, verify)
        self.assertIn("if (result == EALREADY)", refresh)
        self.assertIn("if (result == 0)", refresh)
        self.assertIn("gRootHideAppsRefreshInFlight = result == ETIMEDOUT", refresh)
        self.assertIn("result == EAGAIN", refresh)
        self.assertIn("result == EEXIST", refresh)
        self.assertIn("after-explicit-refresh", refresh)
        self.assertNotIn("rebootUserspace", refresh)
        self.assertNotIn("registerApplicationDictionary", refresh)


if __name__ == "__main__":
    unittest.main()
