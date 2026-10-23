"""Contracts for one-button RootHide3 diagnostics and isolated constructor stages.

Host tests don't prove launchd, dyld or tweak loading on an actual iPhone.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ENV = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m"
ENV_HEADER = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.h"
UI = ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m"
HOOK = ROOT / "BaseBin/systemhook/src/main.c"
PROBE = ROOT / "BaseBin/tweakprobe/main.c"


class RootHideFullDiagnosticTests(unittest.TestCase):
    def test_one_button_launches_aggregator_and_immediate_share_sheet(self):
        ui = UI.read_text(encoding="utf-8")
        header = ENV_HEADER.read_text(encoding="utf-8")
        self.assertIn("- (int)diagnoseRootHideComprehensive;", header)
        self.assertIn('Diagnóstico integral RootHide3 (un botón)', ui)
        self.assertEqual(ui.count('[specifiers addObject:diagnoseAll]'), 1)
        self.assertNotIn('[specifiers addObject:diagnoseRuntime]', ui)
        self.assertNotIn('[specifiers addObject:probeTweaks]', ui)
        self.assertNotIn('[specifiers addObject:sshSocket]', ui)
        action = ui.split("- (void)diagnoseRootHideAllPressed", 1)[1].split(
            "- (void)diagnoseRootHideRuntimePressed", 1)[0]
        for required in ("gRootHideFullDiagnosisInFlight", "diagnoseRootHideComprehensive",
                         "rh3PreviousDiagnosticURL", "UIActivityViewController",
                         "presentViewController:share"):
            self.assertIn(required, action)
        for unsafe in ("repairRootHideSSH", "rebootUserspace", "refreshJailbreakApps",
                       "setTweakInjectionEnabled", "reinstallPackageManagers"):
            self.assertNotIn(unsafe, action)

    def test_inventory_whitelists_components_keeps_failures_partial_and_does_not_mutate_services(self):
        source = ENV.read_text(encoding="utf-8")
        body = source.split("- (int)diagnoseRootHideComprehensive", 1)[1].split(
            "// Explicit, opt-in repair", 1)[0]
        for stage in ("RH3DiagnosticNodeKind", "RH3DiagnosticMachMagic",
                      "rootHideExistingRootWithError:", "jbclient_get_jbroot()",
                      "diagnoseRootHideRuntime", "diagnoseRootHideOpenSSHSocket",
                      "verifyRootHideTweakInjection", "FULL DIAG END",
                      "component=", "no connection sent"):
            self.assertIn(stage, body)
        self.assertLess(body.index("diagnoseRootHideRuntime"),
                        body.index("diagnoseRootHideOpenSSHSocket"))
        self.assertLess(body.index("diagnoseRootHideOpenSSHSocket"),
                        body.index("verifyRootHideTweakInjection"))
        for forbidden in ("repairRootHideSSH", "ssh-keygen", "kickstart", "bootstrap system",
                          "refreshJailbreakApps", "rebootUserspace", "changeMobilePassword:",
                          "setTweakInjectionEnabled:", "updateBootLogo", "exec_cmd("):
            self.assertNotIn(forbidden, body)

    def test_probe_stages_do_not_change_global_process_hooks(self):
        hook = HOOK.read_text(encoding="utf-8")
        source = ENV.read_text(encoding="utf-8")
        probe_run = source.split("- (int)rh3RunCommand:", 1)[1].split(
            "- (int)refreshJailbreakApps", 1)[0]
        self.assertIn('RH3_TWEAK_PROBE_TARGET', hook)
        self.assertIn('RH3_TWEAK_PROBE_ENTERED', hook)
        self.assertIn('RH3_TWEAK_PROBE_CHECKIN', hook)
        self.assertIn('rh3DiagnosticProbe && string_has_suffix', hook)
        self.assertIn('jbclient_trust_library_recurse(probeHookPath.fileSystemRepresentation, NULL)', probe_run)
        self.assertIn('if (probeEnvironment && probeHookPath)', probe_run)
        self.assertIn('hookInfo.st_uid != 0', probe_run)

    def test_actual_probe_executable_distinguishes_all_stages(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("host C compiler not found")
        src = PROBE.read_text(encoding="utf-8").replace("int main(void)", "int rh3_probe_main(void)")
        test = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void reset_probe(void) {
  unsetenv("RH3_TWEAK_PROBE_ENTERED");
  unsetenv("RH3_TWEAK_PROBE_CHECKIN");
  unsetenv("RH3_TWEAK_PROBE_SYSTEMHOOK");
  unsetenv("RH3_TWEAK_PROBE_LOADER");
}
int main(void) {
  reset_probe(); if(rh3_probe_main()!=81) return 1;
  setenv("RH3_TWEAK_PROBE_ENTERED","1",1);
  if(rh3_probe_main()!=83) return 2;
  setenv("RH3_TWEAK_PROBE_CHECKIN","1",1);
  if(rh3_probe_main()!=84) return 3;
  setenv("RH3_TWEAK_PROBE_SYSTEMHOOK","1",1);
  if(rh3_probe_main()!=82) return 4;
  setenv("RH3_TWEAK_PROBE_LOADER","1",1);
  if(rh3_probe_main()!=0) return 5;
  reset_probe(); if(rh3_probe_main()!=81) return 6;
  return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "probe.c"
            exe = Path(directory) / "probe.exe"
            p.write_text("#define _POSIX_C_SOURCE 200809L\n" + src + "\n" + test, encoding="utf-8")
            built = subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", str(p), "-o", str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(exe)], capture_output=True, text=True, timeout=5)
            self.assertEqual(ran.returncode, 0, ran.stderr)


if __name__ == "__main__":
    unittest.main()
