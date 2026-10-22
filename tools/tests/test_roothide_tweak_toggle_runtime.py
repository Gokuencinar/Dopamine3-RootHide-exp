"""Source regressions for RootHide injection activation persistence.

Only the first jailbreak must enter the no-tweak mode; existing installations
must preserve the user's explicit choice and reject unsuccessful toggles.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RuntimeTweakSwitch(unittest.TestCase):
    def test_runtime_switch_reads_real_marker_with_root_privileges(self):
        env = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(encoding="utf-8")
        getter = env.split("- (BOOL)isTweakInjectionEnabled", 1)[1].split("- (int)setTweakInjectionEnabled", 1)[0]
        self.assertIn("rh3PerformPrivilegedAction:", getter)
        self.assertIn("rootHideExistingRootWithError:&rootError", getter)
        self.assertIn("jbclient_get_jbroot()", getter)
        self.assertIn("lstat(marker.fileSystemRepresentation, &info)", getter)
        self.assertIn("markerPresent = YES;", getter)
        self.assertIn("markerPresent = NO;", getter)
        self.assertIn("if (result)", getter)
        self.assertIn("return !markerPresent;", getter)

    def test_existing_bootstrap_no_longer_forces_safe_mode(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text(encoding="utf-8")
        hook = source.split("- (NSError *)injectRootHideLaunchdHookSafely", 1)[1].split(
            "- (NSError *)injectLaunchdHook", 1)[0]
        self.assertIn('installedInfo.st_uid != 0', hook)
        self.assertIn('isEqualToString:@"3"', hook)
        self.assertIn('if (!installed) {', hook)
        self.assertLess(hook.index('if (!installed) {'), hook.index('writeToFile:safeMode atomically:YES'))
        self.assertIn('launchd: first activation; no-tweak mode enforced', hook)
        self.assertIn('launchd: existing bootstrap; saved no-tweak marker present=', hook)

    def test_toggle_stages_only_and_never_reboots_while_pending(self):
        env = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(encoding="utf-8")
        body = env.split("- (int)setTweakInjectionEnabled:", 1)[1].split(
            "- (BOOL)isIDownloadEnabled", 1)[0]
        self.assertIn('rh3PerformPrivilegedAction:', body)
        self.assertIn('rh3_tweak_request_stage', body)
        self.assertIn('S_ISREG(info.st_mode) || info.st_uid != 0', body)
        self.assertNotIn('unlink(safeModePath.fileSystemRepresentation)', body)
        self.assertIn('if (status == 0 && stagedPending) status = EINPROGRESS', body)
        self.assertIn('return [self rh3ActionStage:', body)
        ui = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m").read_text(encoding="utf-8")
        setting = ui.split("- (void)setTweakInjectionEnabled:", 1)[1].split(
            "- (id)readAppJITEnabled:", 1)[0]
        self.assertIn('int status = [envManager setTweakInjectionEnabled:', setting)
        self.assertLess(setting.index('if ([DOBootstrapper rootHidePortEnabled] && status)'),
                        setting.index('rebootUserspace'))
        self.assertIn('No se cambió la inyección', setting)
        self.assertIn('setPreferenceValue:@(envManager.isTweakInjectionEnabled)', setting)
        self.assertIn('status == EINPROGRESS', setting)
        self.assertLess(setting.index('status == EINPROGRESS'), setting.index('rebootUserspace'))

    def test_runtime_diagnostics_are_read_only_and_exclude_private_values(self):
        env = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(encoding="utf-8")
        body = env.split("- (int)diagnoseRootHideRuntime", 1)[1].split(
            "// Explicit, opt-in repair for the OpenSSH", 1)[0]
        self.assertIn('rootHideExistingRootWithError:&rootError', body)
        self.assertIn('jbclient_get_jbroot()', body)
        for name in ("tweak_safe_mode", "tweak_loader_present", "newterm_bundle_present",
                     "sshd_binary_present", "ssh_plists", "daemon_listing_ok"):
            self.assertIn(name, body)
        self.assertIn('![lower containsString:@"shsh"]', body)
        for name in ("sshd_executable=", "ssh_config_present=", "ssh_host_key_files=",
                     "ssh_launch_program_rooted=", "ssh_launch_program_accessible="):
            self.assertIn(name, body)
        for forbidden in ("launchctl", "kickstart", "uicache", "install_pkg",
                          "dpkg", "exec_cmd", "rebootUserspace", "writeToFile",
                          "password", "sshd -D"):
            self.assertNotIn(forbidden, body)
        ui = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m").read_text(encoding="utf-8")
        self.assertIn('@"Diagnosticar tweaks, NewTerm y SSH"', ui)
        self.assertIn('diagnoseRootHideRuntimePressed', ui)


if __name__ == "__main__":
    unittest.main()
