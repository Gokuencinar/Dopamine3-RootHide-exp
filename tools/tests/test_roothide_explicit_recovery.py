"""Exercise independent recovery journals and stop-on-first-failure setup sequencing."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
DIRECTORY = ROOT / 'Application/Dopamine/Jailbreak'

class ExplicitRecovery(unittest.TestCase):
    def test_retry_is_explicit_cold_boot_only_and_never_replays_failed_tree(self):
        source = (DIRECTORY / 'DOBootstrapper.m').read_text(encoding='utf-8')
        policy = source.split('static NSError *RH3RetryRecoveryEligibility(',1)[1].split('@interface',1)[0]
        for item in ('!RH3RecoveryRequested', 'geteuid() != 0', 'majorVersion != 16',
                     'boot.tv_sec <= marker.st_mtime', 'boot.tv_sec <= marker.st_ctime',
                     'proc_listallpids', 'proc_pidpath', 'RH3InstalledMarker', 'RH3CheckBootstrapProfile(root, 1900)'):
            self.assertIn(item, policy)
        for forbidden in ('exec_cmd', 'removeItemAtPath', 'unlink(', 'RH3WritePendingState'):
            self.assertNotIn(forbidden, policy)
        setup = source.split('BOOL freshRecovery =',1)[1].split('BOOL ranInitialSetup',1)[0]
        self.assertLess(setup.index('RH3WritePendingState(root, @"running-script")'), setup.index('RH3RunFreshSetup('))
        self.assertLess(setup.index('RH3RunFreshSetup('), setup.index('unlinkat(directory, "prep_bootstrap.sh"'))
        self.assertIn('RH3FreeShellEnvironment(scriptEnvironment)', setup)

    @unittest.skipUnless(sys.platform == 'darwin', 'actual Foundation filesystem operations require macOS')
    def test_independent_retry_collision_crash_resume_and_immutable_original(self):
        self.compile_and_run(r'''
#import <Foundation/Foundation.h>
static int calls, failAt;
static int faultRename(int a,const char*b,int c,const char*d) {
    if (++calls == failAt) { errno=EIO; return -1; }
    return renameatx_np(a,b,c,d,RENAME_EXCL);
}
#define RH3_RECOVERY_RENAME(a,b,c,d) faultRename(a,b,c,d)
#include "RootHideRecovery.h"
int main(void) { @autoreleasepool {
    char tmp[]="/tmp/rh3-retry-XXXXXX"; if (!mkdtemp(tmp)) return 1;
    NSString *base=@(tmp), *p=[base stringByAppendingPathComponent:@"p"], *s=[base stringByAppendingPathComponent:@"s"];
    NSString *old=@".jbroot-0100000000000001", *next=@".jbroot-0200000000000002";
    NSFileManager *fm=NSFileManager.defaultManager; NSError *error=nil;
    for(NSString *parent in @[p,s]) {
        [fm createDirectoryAtPath:[parent stringByAppendingPathComponent:old] withIntermediateDirectories:YES attributes:nil error:nil];
        [@"original" writeToFile:[[parent stringByAppendingPathComponent:old] stringByAppendingPathComponent:@"sentinel"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    if(!RH3RecoveryPreserve(p,s,old,getuid(),&error)) return 2;
    NSString *journal=[p stringByAppendingPathComponent:RH3RecoveryJournalName];
    NSData *before=[NSData dataWithContentsOfFile:journal];
    struct stat identity; if(lstat(journal.fileSystemRepresentation,&identity)) return 3;
    for(NSString *parent in @[p,s]) {
        [fm createDirectoryAtPath:[parent stringByAppendingPathComponent:next] withIntermediateDirectories:NO attributes:nil error:nil];
        [@"running-script" writeToFile:[[parent stringByAppendingPathComponent:next] stringByAppendingPathComponent:@".installing_roothide3"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    // A destination collision preserves both originals and refuses overwriting.
    NSString *collision=[s stringByAppendingPathComponent:RH3RecoveryBackupName(next)];
    [fm createDirectoryAtPath:collision withIntermediateDirectories:NO attributes:nil error:nil];
    if(RH3RecoveryPreserveRetry(p,s,next,getuid(),&error) || !error) return 4;
    // Only the fixture-created empty collision is removed to exercise resumption.
    [fm removeItemAtPath:collision error:nil]; error=nil;
    failAt=calls+2;
    if(RH3RecoveryPreserveRetry(p,s,next,getuid(),&error) || !error) return 5;
    NSDictionary *pending=RH3RecoveryInspect(p,s,getuid(),&error);
    if(!pending || [pending[@"Complete"] boolValue]) return 6;
    failAt=0; error=nil;
    if(!RH3RecoveryPreserveRetry(p,s,next,getuid(),&error)) return 7;
    NSDictionary *done=RH3RecoveryInspect(p,s,getuid(),&error);
    if(![done[@"Complete"] boolValue] || ![done[@"Name"] isEqual:next]) return 8;
    struct stat after; if(lstat(journal.fileSystemRepresentation,&after) || after.st_ino != identity.st_ino || ![before isEqual:[NSData dataWithContentsOfFile:journal]]) return 9;
    for(NSString *parent in @[p,s]) {
        if(![[NSString stringWithContentsOfFile:[[parent stringByAppendingPathComponent:RH3RecoveryBackupName(old)] stringByAppendingPathComponent:@"sentinel"] encoding:NSUTF8StringEncoding error:nil] isEqual:@"original"]) return 10;
        if(![[NSString stringWithContentsOfFile:[[parent stringByAppendingPathComponent:RH3RecoveryBackupName(next)] stringByAppendingPathComponent:@".installing_roothide3"] encoding:NSUTF8StringEncoding error:nil] isEqual:@"running-script"]) return 11;
    }
    error=nil;
    if(RH3RecoveryPreserveRetry(p,s,@".jbroot-0300000000000003",getuid(),&error) || !error) return 12;
    [fm removeItemAtPath:base error:nil]; return 0;
}}
''')

    @unittest.skipUnless(sys.platform == 'darwin', 'actual Foundation blocks require macOS')
    def test_setup_probes_precede_packages_and_every_failure_stops_sequence(self):
        self.compile_and_run(r'''
#import <Foundation/Foundation.h>
#include "RootHideFreshSetup.h"
int main(void) { @autoreleasepool {
    for(int fail=0;fail<=13;fail++) {
        __block int count=0;
        int result=RH3RunFreshSetup(^int(NSString *label, NSString *command) {
            ++count;
            if(count==1 && ![label isEqual:@"probe-spawn"]) return 900;
            if(count==2 && ![label isEqual:@"probe-setexec"]) return 901;
            return count==fail ? 137 : 0;
        });
        if(result != (fail ? 137 : 0) || count != (fail ?: 13)) return fail+1;
    }
    return 0;
}}
''')

    @unittest.skipUnless(sys.platform == 'darwin', 'actual child wait requires macOS')
    def test_raw_wait_preserves_signal_vs_exit_137(self):
        self.compile_and_run(r'''
#import <Foundation/Foundation.h>
#include <signal.h>
#include "RootHideScriptWait.h"
int main(void) {
    int raw=-1; pid_t p=fork(); if(p<0) return 1; if(!p) _exit(137);
    if(RH3WaitForBootstrapChildStatus(p,3,&raw)!=137 || !WIFEXITED(raw) || WEXITSTATUS(raw)!=137) return 2;
    p=fork(); if(p<0) return 3; if(!p) { raise(SIGKILL); _exit(0); }
    if(RH3WaitForBootstrapChildStatus(p,3,&raw)!=137 || !WIFSIGNALED(raw) || WTERMSIG(raw)!=SIGKILL) return 4;
    return 0;
}
''')

    def compile_and_run(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/'test.m'; binary=Path(tmp)/'test'
            file.write_text(source,encoding='utf-8')
            build=subprocess.run(['xcrun','clang','-fobjc-arc','-fblocks','-include','errno.h','-include','stdio.h','-I',str(DIRECTORY),str(file),'-framework','Foundation','-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(build.returncode,0,build.stderr)
            run=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)

if __name__=='__main__': unittest.main()
