"""Source guardrails for unresponsive RootHide patch daemon and donor password loop.

Safety contracts only; no automated hardware-side recovery is attempted.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
BOOT = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(encoding="utf-8")
UTIL_H = (ROOT / "BaseBin/libjailbreak/src/util.h").read_text(encoding="utf-8")
UTIL_C = (ROOT / "BaseBin/libjailbreak/src/util.c").read_text(encoding="utf-8")
CLI = (ROOT / "BaseBin/dopamine/src/main.m").read_text(encoding="utf-8")


class RootHideBootstrapDaemonPreflight(unittest.TestCase):
    def test_preflight_checks_do_not_mark_script_running(self):
        section = BOOT.split('- (NSError *)finalizeRootHideBootstrap\n{', 1)[1].split(
            '- (NSError *)deleteRootHideBootstrap\n{', 1)[0]
        jbd = section.index('jbdTestCall(23)')
        trust = section.index('jbclient_trust_file_by_path(shell.fileSystemRepresentation)')
        marker = section.index('RH3WritePendingState(root, @"running-script")')
        spawn = section.index('exec_cmd_env_nowait(&scriptPid, scriptEnvironment')
        self.assertLess(jbd, trust)
        self.assertLess(trust, marker)
        self.assertLess(marker, spawn)
        self.assertIn('dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC))', BOOT)
        self.assertIn('daemonReply != 46', section)
        self.assertIn('prepared state retained', section)
        self.assertIn('if ([pending isEqualToString:@"running-script"])', section)
        self.assertNotIn('RH3WritePendingState(root, @"prepared")', section)

    def test_script_environment_skips_donor_infinite_password_prompt(self):
        section = BOOT.split('- (NSError *)finalizeRootHideBootstrap\n{', 1)[1].split(
            '- (NSError *)deleteRootHideBootstrap\n{', 1)[0]
        self.assertIn('setenv("NO_PASSWORD_PROMPT", "1", 1);', CLI)
        self.assertIn('scriptEnvironment[kept++] = strdup("NO_PASSWORD_PROMPT=1");', section)
        self.assertIn('strncmp(*entry, "NO_PASSWORD_PROMPT="', section)
        self.assertIn('RH3FreeShellEnvironment(scriptEnvironment);', section)
        self.assertIn('strdup(*entry)', section)
        self.assertIn('bootstrap: shell spawn returned %d (pid %d)', section)
        self.assertIn('bootstrap: waiting for setup script process exit', section)
        self.assertNotIn('setenv("NO_PASSWORD_PROMPT"', section)
        self.assertIn('int exec_cmd_env_nowait(pid_t *pidOut, char **envp, const char *binary, ...);', UTIL_H)
        func = UTIL_C.split('int exec_cmd_env_nowait(', 1)[1].split('int exec_cmd_suspended(', 1)[0]
        self.assertIn('__exec_cmd_internal_va(false, false, false, pidOut, binary, argc, args, envp)', func)


if __name__ == '__main__':
    unittest.main()
