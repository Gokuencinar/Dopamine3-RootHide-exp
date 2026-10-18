"""Exercise the actual preservation journal, crash resumption and child wait."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT / 'Application/Dopamine/Jailbreak'
SOURCE = (DIRECTORY / 'DOBootstrapper.m').read_text(encoding='utf-8')


class LegacyPreservation(unittest.TestCase):
    def test_recovery_requires_pinned_unfinished_bootstrap_and_later_cold_boot(self):
        policy = SOURCE.split('static NSError *RH3LegacyRecoveryEligibility(', 1)[1].split('@interface', 1)[0]
        for required in ('geteuid() != 0', 'majorVersion != 16', 'RH3CheckBootstrapProfile(root, 1900)',
                         'boot.tv_sec <= marker.st_mtime', 'boot.tv_sec <= marker.st_ctime',
                         'KERN_BOOTTIME', '@"etc/pwd.db"', '@"etc/spwd.db"', '@".installed_roothide3"',
                         '558c08def3e1c8481f0c7a3a0fa9dd1299af5c91f510067f098787d693bdf13c',
                         'c48a3d0c49d5d71f06d0d041330aa53b144591f72bda2208a305be09ca730489'):
            self.assertIn(required, policy)
        self.assertNotIn('master.passwd', policy)
        preserve = SOURCE.split('+ (NSError *)preserveInterruptedRootHideBootstrap', 1)[1].split('+ (BOOL)rootHidePortEnabled', 1)[0]
        self.assertLess(preserve.index('RH3LegacyRecoveryEligibility(root)'), preserve.index('RH3RecoveryPreserve('))
        for forbidden in ('unlink(', 'removeItemAtPath:', 'RH3WritePendingState(', 'exec_cmd(', 'posix_spawn('):
            self.assertNotIn(forbidden, preserve)
        installer = (DIRECTORY / 'DOJailbreaker.m').read_text(encoding='utf-8')
        self.assertIn('if ([DOBootstrapper rootHidePortEnabled] && !removeJailbreakEnabled)', installer)
        self.assertLess(installer.index('preserveInterruptedRootHideBootstrap'), installer.index('ensureJailbreakRootExists'))
        self.assertLess(installer.index('preserveInterruptedRootHideBootstrap'), installer.index('*errOut = [self injectLaunchdHook]'))

    def test_new_launch_is_bounded_without_releasing_worker_environment_on_timeout(self):
        launch = SOURCE.split('dispatch_group_t launch = dispatch_group_create();', 1)[1].split(
            'bootstrap: prep_bootstrap.sh returned', 1)[0]
        self.assertIn('20 * NSEC_PER_SEC', launch)
        self.assertIn('RH3WaitForBootstrapChild(scriptPid, 180)', launch)
        worker, remainder = launch.split('});', 1)
        self.assertIn('RH3FreeShellEnvironment(scriptEnvironment)', worker)
        self.assertNotIn('RH3FreeShellEnvironment(scriptEnvironment)', remainder)
        self.assertNotIn('RH3WritePendingState(', launch)

    @unittest.skipUnless(sys.platform == 'darwin', 'actual Foundation filesystem tests require macOS')
    def test_actual_preservation_and_crash_resumption(self):
        harness = r'''
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <errno.h>
static int calls = 0, failAt = 0;
static int faultRename(int a, const char *b, int c, const char *d) {
    if (++calls == failAt) { errno = EIO; return -1; }
    return renameatx_np(a,b,c,d,RENAME_EXCL);
}
#define RH3_RECOVERY_RENAME(a,b,c,d) faultRename(a,b,c,d)
#include "RootHideRecovery.h"
int main(int argc, char **argv) { @autoreleasepool {
    int scenario = atoi(argv[1]);
    char template[] = "/tmp/rh3-preservation-XXXXXX";
    char *base = mkdtemp(template); if (!base) return 10;
    NSString *top = @(base), *p = [top stringByAppendingPathComponent:@"p"], *s = [top stringByAppendingPathComponent:@"s"];
    NSString *name = @".jbroot-0100000000000001", *backup = RH3RecoveryBackupName(name);
    NSFileManager *fm = NSFileManager.defaultManager;
    for (NSString *parent in @[p,s]) {
        [fm createDirectoryAtPath:[parent stringByAppendingPathComponent:name] withIntermediateDirectories:YES attributes:nil error:nil];
        [@"sentinel" writeToFile:[[parent stringByAppendingPathComponent:name] stringByAppendingPathComponent:@"data"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    NSString *original = [p stringByAppendingPathComponent:name], *second = [s stringByAppendingPathComponent:name];
    symlink(original.fileSystemRepresentation,[second stringByAppendingPathComponent:@".jbroot"].fileSystemRepresentation);
    NSString *marker = [original stringByAppendingPathComponent:@".installing_roothide3"];
    [@"running-script" writeToFile:marker atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSError *error = nil;
    if (scenario == 2) [fm createDirectoryAtPath:[p stringByAppendingPathComponent:backup] withIntermediateDirectories:NO attributes:nil error:nil];
    if (scenario == 3) {
        NSString *journal = [p stringByAppendingPathComponent:RH3RecoveryJournalName];
        [@"corrupt" writeToFile:journal atomically:YES encoding:NSUTF8StringEncoding error:nil]; chmod(journal.fileSystemRepresentation,0600);
    }
    if (scenario == 4) { [fm moveItemAtPath:original toPath:[p stringByAppendingPathComponent:@"real"] error:nil]; symlink("real",original.fileSystemRepresentation); }
    if (scenario == 9) { symlink("missing",[p stringByAppendingPathComponent:RH3RecoveryJournalName].fileSystemRepresentation); }
    if (scenario == 1 || scenario == 5 || scenario == 13) failAt = 2;
    if (scenario == 8) failAt = 1;
    BOOL result = RH3RecoveryPreserve(p,s,scenario == 7 ? @"../escape" : name, scenario == 6 ? getuid()+1 : getuid(),&error);
    if (scenario == 2 || scenario == 3 || scenario == 4 || scenario == 6 || scenario == 7 || scenario == 9) {
        if (result || !error || ![fm fileExistsAtPath:second]) return 20;
        if (scenario == 2 && ![error.localizedDescription containsString:@"reason=original-and-backup-both-present"]) return 32;
    } else {
        if (scenario == 1 || scenario == 5 || scenario == 8 || scenario == 13) {
            if (result || !error) return 21;
            error = nil;
            NSDictionary *state = RH3RecoveryInspect(p,s,getuid(),&error);
            if (!state || error || [state[@"Complete"] boolValue]) return 22;
            if (scenario == 13) {
                NSString *journal = [p stringByAppendingPathComponent:RH3RecoveryJournalName];
                NSMutableDictionary *record = [[NSDictionary dictionaryWithContentsOfFile:journal] mutableCopy];
                for (NSString *key in @[@"PrimaryIdentity", @"SecondaryIdentity"]) {
                    NSArray *identity = record[key];
                    record[key] = @[@([identity[0] unsignedLongLongValue]+1), identity[1]];
                }
                NSData *bytes = [NSPropertyListSerialization dataWithPropertyList:record format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
                [bytes writeToFile:journal atomically:NO];
                int before = calls;
                if (RH3RecoveryInspect(p,s,getuid(),&error) || !error ||
                    ![error.localizedDescription containsString:@"complete=0"]) return 37;
                error = nil;
                if (RH3RecoveryPreserve(p,s,name,getuid(),&error) || !error || calls != before) return 38;
                if (![fm fileExistsAtPath:second]) return 39;
                [fm removeItemAtPath:top error:nil]; return 0;
            }
            if (scenario == 5) {
                [fm moveItemAtPath:second toPath:[s stringByAppendingPathComponent:@"other"] error:nil];
                [fm createDirectoryAtPath:second withIntermediateDirectories:NO attributes:nil error:nil];
                failAt = 0;
                if (RH3RecoveryPreserve(p,s,name,getuid(),&error) || !error) return 23;
                if (![error.localizedDescription containsString:@"reason=container-inode-changed"] ||
                    ![error.localizedDescription containsString:@"container=secondary"]) return 33;
                [fm removeItemAtPath:top error:nil]; return 0;
            }
            failAt = 0;
            if (!RH3RecoveryPreserve(p,s,name,getuid(),&error)) return 24;
        } else if (!result) { NSLog(@"%@",error); return 25; }
        error = nil;
        NSDictionary *state = RH3RecoveryInspect(p,s,getuid(),&error);
        if (!state || error || ![state[@"Complete"] boolValue]) return 26;
        if (scenario == 12 || scenario == 14 || scenario == 15) {
            NSString *journal = [p stringByAppendingPathComponent:RH3RecoveryJournalName];
            NSMutableDictionary *record = [[NSDictionary dictionaryWithContentsOfFile:journal] mutableCopy];
            for (NSString *key in @[@"PrimaryIdentity", @"SecondaryIdentity"]) {
                NSArray *identity = record[key];
                record[key] = @[@([identity[0] unsignedLongLongValue]+1), identity[1]];
            }
            if (scenario == 14) {
                NSArray *identity = record[@"SecondaryIdentity"];
                record[@"SecondaryIdentity"] = @[identity[0], @([identity[1] unsignedLongLongValue]+1)];
            }
            if (scenario == 15) [fm createDirectoryAtPath:original withIntermediateDirectories:NO attributes:nil error:nil];
            NSData *bytes = [NSPropertyListSerialization dataWithPropertyList:record format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
            [bytes writeToFile:journal atomically:NO];
            error = nil;
            state = RH3RecoveryInspect(p,s,getuid(),&error);
            if (scenario == 12) {
                if (!state || error || ![state[@"Complete"] boolValue] || ![state[@"CompletedDeviceChange"] boolValue]) return 40;
                int before = calls;
                if (!RH3RecoveryPreserve(p,s,name,getuid(),&error) || calls != before) return 41;
                if (![[NSData dataWithContentsOfFile:journal] isEqual:bytes]) return 42;
                if ([fm fileExistsAtPath:original] || [fm fileExistsAtPath:second]) return 43;
                NSString *savedMarker = [[p stringByAppendingPathComponent:backup] stringByAppendingPathComponent:@".installing_roothide3"];
                if (![[NSString stringWithContentsOfFile:savedMarker encoding:NSUTF8StringEncoding error:nil] isEqual:@"running-script"]) return 44;
            } else {
                NSString *reason = scenario == 14 ? @"reason=container-inode-changed" : @"reason=original-and-backup-both-present";
                if (state || !error || ![error.localizedDescription containsString:reason]) return 45;
            }
            for (NSString *parent in @[p,s])
                if (![[NSString stringWithContentsOfFile:[[parent stringByAppendingPathComponent:backup] stringByAppendingPathComponent:@"data"] encoding:NSUTF8StringEncoding error:nil] isEqual:@"sentinel"]) return 46;
            [fm removeItemAtPath:top error:nil]; return 0;
        }
        if (scenario == 10 || scenario == 11) {
            NSString *journal = [p stringByAppendingPathComponent:RH3RecoveryJournalName];
            NSData *bytes = [NSData dataWithContentsOfFile:journal];
            NSMutableDictionary *record = [[NSPropertyListSerialization propertyListWithData:bytes options:NSPropertyListImmutable format:NULL error:nil] mutableCopy];
            NSMutableArray *identity = [record[@"PrimaryIdentity"] mutableCopy];
            NSUInteger slot = scenario == 10 ? 0 : 1;
            identity[slot] = @([identity[slot] unsignedLongLongValue] + 1);
            record[@"PrimaryIdentity"] = identity;
            bytes = [NSPropertyListSerialization dataWithPropertyList:record format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
            [bytes writeToFile:journal atomically:NO];
            error = nil;
            if (RH3RecoveryInspect(p,s,getuid(),&error) || !error) return 34;
            NSString *reason = scenario == 10 ? @"reason=container-device-changed" : @"reason=container-inode-changed";
            if (![error.localizedDescription containsString:reason]) return 35;
            if (scenario == 10 && ![error.localizedDescription containsString:@"recorded_devs="]) return 47;
            if (scenario == 11 && (![error.localizedDescription containsString:@"container=primary"] ||
                ![error.localizedDescription containsString:@"expected_dev="] ||
                ![error.localizedDescription containsString:@"backup={mode="])) return 48;
            if (![fm fileExistsAtPath:[[p stringByAppendingPathComponent:backup] stringByAppendingPathComponent:@"data"]]) return 36;
            [fm removeItemAtPath:top error:nil]; return 0;
        }
        if ([fm fileExistsAtPath:original] || [fm fileExistsAtPath:second]) return 27;
        for (NSString *location in state[@"Locations"]) {
            if (![[NSString stringWithContentsOfFile:[location stringByAppendingPathComponent:@"data"] encoding:NSUTF8StringEncoding error:nil] isEqual:@"sentinel"]) return 28;
        }
        NSString *savedMarker = [[p stringByAppendingPathComponent:backup] stringByAppendingPathComponent:@".installing_roothide3"];
        if (![[NSString stringWithContentsOfFile:savedMarker encoding:NSUTF8StringEncoding error:nil] isEqual:@"running-script"]) return 29;
        NSString *savedLink = [[s stringByAppendingPathComponent:backup] stringByAppendingPathComponent:@".jbroot"];
        if (![[fm destinationOfSymbolicLinkAtPath:savedLink error:nil] isEqual:original]) return 31;
        if (!RH3RecoveryPreserve(p,s,name,getuid(),&error)) return 30;
    }
    [fm removeItemAtPath:top error:nil]; return 0;
} }
'''
        self._compile_and_run(harness, range(16), foundation=True)

    @unittest.skipUnless(sys.platform == 'darwin', 'POSIX child process tests require macOS')
    def test_actual_child_exit_signal_and_timeout(self):
        harness = r'''
#include <signal.h>
#include "RootHideScriptWait.h"
int main(void) {
    if (RH3WaitForBootstrapChild(0,0) != -EINVAL) return 1;
    pid_t pid = fork(); if (pid < 0) return 2;
    if (!pid) _exit(7);
    if (RH3WaitForBootstrapChild(pid,2) != 7) return 3;
    if (RH3WaitForBootstrapChild(pid,0) != -ECHILD) return 4;
    pid = fork(); if (pid < 0) return 5;
    if (!pid) { raise(SIGTERM); _exit(8); }
    if (RH3WaitForBootstrapChild(pid,2) != 128+SIGTERM) return 6;
    pid = fork(); if (pid < 0) return 7;
    if (!pid) { sleep(10); _exit(0); }
    int result = RH3WaitForBootstrapChild(pid,0);
    int alive = kill(pid,0);
    kill(pid,SIGKILL); waitpid(pid,0,0);
    return result == -ETIMEDOUT && alive == 0 ? 0 : 8;
}
'''
        self._compile_and_run(harness, [None], foundation=False)

    def _compile_and_run(self, harness, cases, foundation):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / ('test.m' if foundation else 'test.c')
            binary = Path(directory) / 'test'
            source.write_text(harness, encoding='utf-8')
            command = ['xcrun', 'clang', '-I', str(DIRECTORY), str(source), '-o', str(binary)]
            if foundation: command += ['-fobjc-arc', '-framework', 'Foundation']
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            for case in cases:
                result = subprocess.run([str(binary)] + ([] if case is None else [str(case)]), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, f'scenario {case}: {result.stderr}')


if __name__ == '__main__':
    unittest.main()
