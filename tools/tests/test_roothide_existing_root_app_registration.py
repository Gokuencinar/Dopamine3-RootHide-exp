"""Existing RootHide bootstrap app registration contracts.

Windows cannot query iOS LaunchServices or execute RootHide uicache. These
checks guard the actual reactivation path and prohibit silent package writes;
a device must still verify that lsd accepts the resulting registration.
"""

from pathlib import Path
import unittest


SOURCE = (Path(__file__).resolve().parents[2] /
          "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(encoding="utf-8")


class ExistingRootRegistration(unittest.TestCase):
    def test_root_rotates_before_finalization_and_registers_existing_apps(self):
        prepare = SOURCE.split('- (void)prepareRootHideBootstrapWithCompletion:', 1)[1].split(
            '- (NSArray<NSString *> *)rootHideSelectedManagerPackagesWithError:', 1)[0]
        self.assertIn('error = [self rh3RerandomizeRoot:&root]', prepare)
        finalize = SOURCE.split('- (NSError *)finalizeRootHideBootstrap\n{', 1)[1].split(
            '- (NSError *)deleteRootHideBootstrap\n{', 1)[0]
        self.assertIn('isEqualToString:@"3"', finalize)
        self.assertLess(finalize.index('RH3RecordInstalledAppInventory(root)'),
                        finalize.index('repairRootHideAppLinks'))
        self.assertLess(finalize.index('repairRootHideAppLinks'),
                        finalize.index('RH3RegisterPinnedJailbreakApps(root, installed)'))
        self.assertLess(finalize.index('RH3RegisterPinnedJailbreakApps(root, installed)'),
                        finalize.index('writeToFile:marker'))
        self.assertIn('if (!installed) return registrationError;', finalize)
        self.assertEqual(finalize.count('RH3RegisterPinnedJailbreakApps(root, installed)'), 1)
        # On an installed root, package managers remain controlled by an
        # explicit reinstall action; this retry only repairs LS metadata.
        self.assertIn('if (!installed) {', finalize)
        self.assertIn('NSError *error = [self installPackageManagers]', finalize)

    def test_registration_is_fixed_scope_and_checks_root_and_identity(self):
        register = SOURCE.split('static NSError *RH3RegisterPinnedJailbreakApps(', 1)[1].split(
            'static void RH3RecordInstalledAppInventory', 1)[0]
        self.assertIn('geteuid() != 0', register)
        self.assertIn('rootHideBrandForPath:root', register)
        self.assertIn('RH3IsRealDirectory(root)', register)
        self.assertIn('root stringByAppendingPathComponent:@"usr/bin/uicache"', register)
        self.assertIn('toolInfo.st_uid != 0', register)
        self.assertIn('toolInfo.st_nlink != 1', register)
        self.assertIn('S_IXUSR', register)
        self.assertIn('rh3_bundle_owner_allowed', register)
        self.assertIn('trustedOwner = terminal ? appInfo.st_uid == 0', register)
        self.assertIn('trustedPlistOwner = plistOnDisk', register)
        self.assertIn('RH3IsNewTermBundleIdentifier(info[@"CFBundleIdentifier"])', register)
        for name in ('Sileo', 'Zebra', 'RootHide', 'NewTerm', 'NewTerm2', 'NewTerm3'):
            self.assertIn('@"' + name + '"', register)
        self.assertNotIn('contentsOfDirectoryAtPath:', register)
        self.assertNotIn('LSApplicationProxy', register)
        self.assertNotIn('dpkg', register.split('static NSError *RH3RegisterPinnedJailbreakApps(', 1)[-1])

    def test_metadata_read_and_spawn_are_bounded_and_fail_closed(self):
        register = SOURCE.split('static NSError *RH3RegisterPinnedJailbreakApps(', 1)[1].split(
            'static void RH3RecordInstalledAppInventory', 1)[0]
        self.assertLess(register.index('lstat(plist.fileSystemRepresentation'),
                        register.index('NSPropertyListSerialization propertyListWithData'))
        self.assertIn('O_RDONLY | O_NOFOLLOW | O_CLOEXEC', register)
        self.assertIn('opened.st_ino == plistInfo.st_ino', register)
        self.assertIn('opened.st_dev == plistInfo.st_dev', register)
        self.assertIn('opened.st_size == plistInfo.st_size', register)
        self.assertIn('plistInfo.st_size <= 64 * 1024', register)
        self.assertIn('jbclient_trust_file_by_path(uicache.fileSystemRepresentation)', register)
        self.assertLess(register.index('jbclient_trust_file_by_path('),
                        register.index('exec_cmd_nowait('))
        self.assertIn('"-p", app.fileSystemRepresentation', register)
        self.assertIn('dispatch_group_wait(launch, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC))', register)
        self.assertIn('RH3WaitForBootstrapChild(child, 30)', register)
        self.assertIn('if (result == -ETIMEDOUT || result == ETIMEDOUT) return problem;', register)
        self.assertIn('outcome unknown', register)
        self.assertNotIn('launchctl', register)
        self.assertNotIn('rm -rf', register)

    def test_newterm_only_recognizes_named_hbang_family(self):
        helper = SOURCE.split('static BOOL RH3IsNewTermBundleIdentifier(', 1)[1].split(
            'static NSError *RH3RegisterPinnedJailbreakApps(', 1)[0]
        self.assertIn('identifier.length > 128', helper)
        self.assertIn('@"ws.hbang.Terminal"', helper)
        self.assertIn('@"com.hbang.NewTerm"', helper)
        self.assertIn('[prefix stringByAppendingString:@"."]', helper)
        self.assertNotIn('hasPrefix:@"ws."', helper)


if __name__ == "__main__":
    unittest.main()
