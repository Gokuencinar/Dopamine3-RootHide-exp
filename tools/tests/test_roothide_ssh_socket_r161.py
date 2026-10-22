"""Safety contracts for the isolated, opt-in OpenSSH socket-state diagnosis."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
ENV = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(encoding="utf-8")
UI = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m").read_text(encoding="utf-8")
HEADER = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.h").read_text(encoding="utf-8")


class SSHSocketDiagnosisR161(unittest.TestCase):
    def setUp(self):
        self.diagnostic = ENV.split("- (int)diagnoseRootHideOpenSSHSocket", 1)[1].split(
            "// Never treat presence of TweakLoader", 1
        )[0]

    def test_ui_is_separate_explicit_action(self):
        self.assertIn('@"Diagnosticar arranque de OpenSSH (solo lectura)"', UI)
        self.assertIn('@"diagnoseRootHideOpenSSHSocketPressed"', UI)
        self.assertIn("diagnoseRootHideOpenSSHSocket;", HEADER)
        self.assertIn("diagnoseRootHideOpenSSHSocket]", UI)

    def test_only_readonly_fixed_launchctl_print(self):
        body = self.diagnostic
        self.assertIn('@"usr/bin/launchctl"', body)
        self.assertIn('"print", "system/com.openssh.sshd", NULL', body)
        self.assertIn("char *const cleanEnv[] = {NULL}", body)
        self.assertIn("posix_spawn(&pid, argv[0], &actions, NULL, argv, cleanEnv)", body)
        for banned in ("kickstart", "bootstrap system", "bootout", "ssh-keygen", "sshd -D",
                       "jbclient_trust_executable_recurse", "exec_cmd_roothide_spawn_traced",
                       "jbdSpawnPatchChild", "chmod(", "chown(", "writeToFile:",
                       "rebootUserspace", "exec_cmd(", '"/bin/launchctl"'):
            self.assertNotIn(banned, body)

    def test_safe_root_and_plist_ownership_and_no_raw_logs(self):
        body = self.diagnostic
        self.assertIn("rootHideExistingRootWithError:&error", body)
        self.assertIn("jbclient_get_jbroot()", body)
        self.assertIn("file.st_uid != 0", body)
        self.assertIn('isEqual:@"com.openssh.sshd"', body)
        self.assertIn('@"inetdCompatibility"', body)
        self.assertIn('@"Wait"', body)
        self.assertIn("RH3SSHCountSocketPorts(entry, &port22Count, &port2222Count)", body)
        self.assertIn('plist[@"Disabled"]', body)
        self.assertIn('programClass = RH3SSHPrintPathClass(output, @"program"', body)
        self.assertIn('originClass = RH3SSHPrintPathClass(output, @"path"', body)
        self.assertIn('configArgSeen', body)
        self.assertIn('keyArgSeen', body)
        self.assertIn('RH3SSHPrintScalar(output, @"last exit code", YES)', body)
        self.assertIn('RH3SSHPrintScalar(output, @"last terminating signal", YES)', body)
        self.assertIn('RH3SSHPrintScalar(output, @"pid", YES)', body)
        self.assertIn('RH3SSHPrintScalar(output, @"state", NO)', body)
        self.assertNotIn("rh3RecordDiagnosticStage:output", body)
        self.assertNotIn("sendLog:output", body)
        self.assertNotIn("program_rooted=", body)
        self.assertNotIn("listeners=%d", body)

    def test_r167_metadata_probe_reports_flags_without_private_values(self):
        body = self.diagnostic
        self.assertIn('SSH socket plist metadata: directory_trusted=%d', body)
        self.assertIn('original_group_trusted=%d', body)
        self.assertIn('original_mode_trusted=%d', body)
        self.assertIn('original_links_trusted=%d', body)
        self.assertIn('backup_state=%d', body)
        self.assertIn('lstat(backupPath.fileSystemRepresentation, &backupInfo)', body)
        self.assertIn('lstat(directory.fileSystemRepresentation, &folder)', body)
        self.assertNotIn('rh3RecordDiagnosticStage:backupPath', body)
        self.assertNotIn('rh3RecordDiagnosticStage:directory', body)

    def test_r162_classifies_without_disclosing_live_paths(self):
        helpers = ENV.split("// launchctl print is a diagnostic format", 1)[1].split(
            "@implementation DOEnvironmentManager", 1
        )[0]
        self.assertIn("static NSString *RH3SSHPrintPathClass", helpers)
        self.assertIn("RH3CanonicalAppPath(value)", helpers)
        self.assertIn("RH3CanonicalAppPath(root)", helpers)
        for classification in ('@"expected"', '@"active_other"', '@"stock_ssh"',
                               '@"var_jb_alias"', '@"other_absolute"', '@"missing"'):
            self.assertIn(classification, helpers)
        self.assertIn('((NSDictionary *)entry)[@"SockServiceName"]', helpers)
        self.assertIn('isEqualToString:@"ssh"', helpers)
        self.assertIn('isEqualToString:@"2222"', helpers)
        self.assertIn('port22=%lu port2222=%lu disabled=%d', self.diagnostic)
        self.assertIn('program_class=%@ origin_class=%@', self.diagnostic)
        self.assertNotIn('rh3RecordDiagnosticStage:[NSString stringWithFormat:@"%@", output]',
                         self.diagnostic)

    def test_differential_plist_vs_launchd_is_read_only_and_non_disclosing(self):
        body = self.diagnostic
        self.assertIn('diskProgram = program', body)
        self.assertIn('RH3SSHPrintPrivatePath(output, @"program")', body)
        self.assertIn('RH3CanonicalAppPath(diskProgram)', body)
        self.assertIn('RH3CanonicalAppPath(liveProgram)', body)
        self.assertIn('int programMatchesPlist = canonicalDisk && canonicalLive', body)
        self.assertIn('disk_program_class=%@ program_matches_plist=%d disabled_override=%@', body)
        self.assertIn('[self rh3OpenSSHDisabledOverrideUsingLaunchctl:binary]', body)
        self.assertNotIn('rh3RecordDiagnosticStage:diskProgram', body)
        self.assertNotIn('rh3RecordDiagnosticStage:liveProgram', body)
        self.assertNotIn('stringWithFormat:@"%@", diskProgram', body)

    def test_disabled_override_uses_exact_label_and_bounded_query(self):
        helper = ENV.split('static NSString *RH3SSHParseDisabledOverride', 1)[1].split(
            '// Procursus names the entries', 1
        )[0]
        self.assertIn('@"\\\"com.openssh.sshd\\\" => "', helper)
        self.assertIn('@"disabled"', helper)
        self.assertIn('@"enabled"', helper)
        self.assertIn('@"true"', helper)
        self.assertIn('@"false"', helper)
        self.assertIn('if (found) return @"unknown"', helper)
        self.assertIn('return found ?: @"no_override"', helper)

        query = ENV.split('- (NSString *)rh3OpenSSHDisabledOverrideUsingLaunchctl:', 1)[1].split(
            '// User-triggered, read-only diagnosis', 1
        )[0]
        self.assertIn('"print-disabled", "system", NULL', query)
        self.assertIn('char *const cleanEnv[] = {NULL}', query)
        self.assertIn('posix_spawn(&pid, argv[0], &actions, NULL, argv, cleanEnv)', query)
        self.assertIn('const NSUInteger maximum = 128 * 1024', query)
        self.assertIn('CLOCK_MONOTONIC', query)
        self.assertIn('WIFEXITED(status)', query)
        for forbidden in ('"enable"', '"disable"', '"kickstart"', '"bootstrap"',
                          '"bootout"', '"sshd"', 'rebootUserspace',
                          'jbclient_trust_executable_recurse', 'rh3RecordDiagnosticStage:output'):
            self.assertNotIn(forbidden, query)

    def test_child_only_bounded_capture(self):
        body = self.diagnostic
        self.assertIn("O_NONBLOCK", body)
        self.assertIn("CLOCK_MONOTONIC", body)
        self.assertIn("const NSUInteger maximum = 16384", body)
        self.assertIn("drainedBytes > 128 * 1024", body)
        self.assertIn("now.tv_sec - start.tv_sec >= 10", body)
        self.assertIn("kill(pid, SIGKILL)", body)
        self.assertIn("waitpid(pid, &childStatus, WNOHANG)", body)
        self.assertIn("exitCode", body)
        self.assertIn("lastExit", body)
        self.assertIn("outputLimit ? EOVERFLOW", body)


if __name__ == "__main__":
    unittest.main()
