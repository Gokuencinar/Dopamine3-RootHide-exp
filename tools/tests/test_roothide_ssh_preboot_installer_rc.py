"""Source-level regression gates for opt-in OpenSSH pre-reboot repair.

These are NOT native iOS transaction tests or evidence of a working SSH banner.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
ENV = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(encoding="utf-8")
JB = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text(encoding="utf-8")
UI = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m").read_text(encoding="utf-8")
PREF = (ROOT / "Application/Dopamine/Jailbreak/DOPreferenceManager.m").read_text(encoding="utf-8")


class RootHideSSHPrebootRC(unittest.TestCase):
    def test_opt_in_is_off_by_default_and_preboot_error_is_nonfatal(self):
        preboot = ENV.split('- (int)prepareRootHideOpenSSHBeforeUserspaceReboot', 1)[1].split(
            '// Read the effective launchd disabled override', 1)[0]
        self.assertIn('@"rh3SSHInstallerRepairOptIn" fallback:NO', preboot)
        self.assertIn('!(flags & CS_INSTALLER)', preboot)
        self.assertIn('!(flags & CS_PLATFORM_BINARY)', preboot)
        self.assertIn('geteuid() != 0 || getegid() != 0', preboot)
        self.assertIn('rh3RepairRootHideSSHAllowKeyGeneration:NO installerPhase:YES', preboot)
        self.assertNotIn('proc_csflags_set', preboot)
        self.assertNotIn('jbclient_dopamine_get_root', preboot)
        start = JB.index('prepareRootHideOpenSSHBeforeUserspaceReboot')
        self.assertLess(JB.index('finalizeBootstrapIfNeeded];'), start)
        self.assertLess(start, JB.index('setIDownloadEnabled:idownloadEnabled needsUnsandbox:NO'))
        self.assertLess(start, JB.index('cleanUpPostExploitation];', start))
        self.assertNotIn('*errOut', JB[start:start + 500])

    def test_boot_root_is_local_and_manual_root_is_fresh(self):
        helper = ENV.split('static NSString *RH3SSHCurrentServerRoot(void)', 1)[1].split(
            'static int RH3SSHRebaseInstalledPlist', 1)[0]
        self.assertIn('JBS_SYSTEMWIDE_GET_JBROOT, NULL', helper)
        self.assertIn('xpc_dictionary_get_string(reply, "root-path")', helper)
        self.assertIn('xpc_release(reply)', helper)
        self.assertIn('if (!installerPhase) return RH3SSHCurrentServerRoot()', helper)
        self.assertIn('gSystemInfo.jailbreakInfo.rootPath', helper)
        repair = ENV.split('- (int)rh3RepairRootHideSSHAllowKeyGeneration:', 1)[1].split(
            '- (int)prepareRootHideOpenSSHBeforeUserspaceReboot', 1)[0]
        self.assertEqual(repair.count('RH3SSHRootForPhase(installerPhase)'), 2)
        self.assertNotIn('jbclient_get_jbroot()', repair)
        self.assertIn('if (needsKey && !allowKeyGeneration)', repair)
        self.assertLess(repair.index('if (needsKey && !allowKeyGeneration)'),
                        repair.index('rh3RunCommand:keygenPath'))
        self.assertIn('installerPhase ? sshPreflight() :', repair)
        self.assertIn('installerPhase ? sshCommit() :', repair)
        self.assertIn('if (!installerPhase) {', repair)
        self.assertIn('sshd -t deferred to avoid a bootstrap-stage stall', repair)
        self.assertIn('@synchronized (self)', repair)

    def test_transient_exact_inode_and_metadata_failure_recovery(self):
        transaction = ENV.split('static int RH3SSHRebaseInstalledPlist(', 1)[1].split(
            '// Procursus names the entries', 1)[0]
        for token in ('before.st_flags != 0', 'flistxattr(original, NULL, 0, 0)',
                      'acl_get_fd_np(original, ACL_TYPE_EXTENDED)',
                      'original_xattrs', 'original_acl',
                      'current.st_ctimespec.tv_nsec', 'current.st_mtimespec.tv_nsec',
                      'RH3SSHReadBounded(original, before.st_size) isEqual:originalData',
                      'linkat(dir, jobName, dir, rollbackName, 0)',
                      'replacement_xattrs', 'replacement_acl',
                      'acl_get_fd_np(replacementRead, ACL_TYPE_EXTENDED)',
                      'renameat(dir, rollbackName, dir, jobName)',
                      'live.st_ino == replacement.st_ino', 'post_replace_rolled_back',
                      'rollback_failed_preserved', 'O_EXCL | O_NOFOLLOW',
                      'renamedJob && result && madeRollback'):
            self.assertIn(token, transaction)
        for recovery in ('pending_rollback_check', 'pending_rollback_cleanup',
                         'before.st_nlink == 2', 'pendingOpened.st_nlink == 2',
                         'committed = [liveOther isEqual:oldOther]',
                         'if (!sameInode && !committed)',
                         'unlinkat(dir, rollbackName, 0) || fsync(dir)'):
            self.assertIn(recovery, transaction)
        self.assertIn('port22 != 1 || port2222 != 1', transaction)
        self.assertIn('for (id socketEntry in sockets.allValues)', transaction)
        self.assertIn('RH3SSHCountSocketPorts(socketEntry, &entry22, &entry2222)', transaction)
        self.assertIn('entry22 + entry2222 != 1', transaction)
        self.assertNotIn('RH3SSHCountSocketPorts(sockets, &port22, &port2222)', transaction)
        self.assertIn('arc4random(), arc4random()', transaction)
        self.assertIn('rootHideBrandForPath:oldRoot', transaction)
        self.assertIn('renameatx_np(dir, backupTempName, dir, backupName, RENAME_EXCL)', transaction)
        self.assertIn('backup_publish_sync', transaction)
        for forbidden in ('job[@"Sockets"] =', 'job[@"inetdCompatibility"] =',
                          'job[@"Disabled"] =', 'launchctl', 'kickstart'):
            self.assertNotIn(forbidden, transaction)

    def test_preboot_toggle_visible_while_unjailbroken_and_is_only_preference(self):
        self.assertLess(UI.index('toggleRootHideSSHPrebootRepairPressed" forKey:@"action"'),
                        UI.index('if (envManager.isBootstrapped)'))
        handler = UI.split('- (void)toggleRootHideSSHPrebootRepairPressed', 1)[1].split(
            '- (void)diagnoseRootHideRuntimePressed', 1)[0]
        self.assertIn('setVerifiedPreferenceValue:@(!enabled)', handler)
        self.assertIn('if (persisted && [onDisk[key] isEqual:obj]) return YES', PREF)
        self.assertIn('if (oldValue) _preferences[key] = oldValue', PREF)
        self.assertIn('SSH pre-import opt-in save failed; consent NOT confirmed', handler)
        self.assertNotIn('repairRootHideSSH]', handler)
        self.assertNotIn('rebootUserspace', handler)
        self.assertNotIn('ssh-keygen', handler)


if __name__ == '__main__':
    unittest.main()
