"""PID1-specific spawn policy, identity and async lifecycle regression gates.

Host C simulation runs the *production* target selector. It does not pretend
to exercise Apple's suspended spawn/launchd machinery on Windows or macOS.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / 'BaseBin/launchdhook/src/roothide_pid1_selected.h'
STATE = ROOT / 'BaseBin/launchdhook/src/roothide_pid1_deferred_state.h'
LAUNCHD = ROOT / 'BaseBin/launchdhook/src/spawn_hook.c'
SERVER = ROOT / 'BaseBin/jailbreakd/src/server.m'
CLIENT = ROOT / 'BaseBin/libjailbreak/src/roothider/jailbreakd.c'


class Pid1DeferredPatch(unittest.TestCase):
    def test_selected_jobs_only_actual_c(self):
        cc = shutil.which('gcc') or shutil.which('clang') or shutil.which('cc')
        if not cc:
            self.skipTest('C compiler unavailable')
        source = r'''
#include "roothide_pid1_selected.h"
#include <stddef.h>
int main(void) {
    const char *ssh = "/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/usr/sbin/sshd";
    char *newterm[] = {"xpcproxy", "UIKitApplication:ws.hbang.Terminal[ABCD]", NULL};
    char *newtermModern[] = {"xpcproxy", "UIKitApplication:com.hbang.NewTerm[ABCD]", NULL};
    char *newtermImpostor[] = {"xpcproxy", "UIKitApplication:com.hbang.NewTermEvil[ABCD]", NULL};
    char *sileo[] = {"xpcproxy", "UIKitApplication:org.coolstar.SileoStore[0]", NULL};
    char *zebra[] = {"xpcproxy", "UIKitApplication:xyz.willy.Zebra[0]", NULL};
    char *rootHide[] = {"xpcproxy", "UIKitApplication:com.roothide.manager[0]", NULL};
    char *apple[] = {"xpcproxy", "UIKitApplication:com.apple.springboard[0]", NULL};
    char *fakeId[] = {"xpcproxy", "UIKitApplication:ws.hbang.TerminalEvil[1]", NULL};
    char *wrongBoundary[] = {"xpcproxy", "UIKitApplication:ws.hbang.Terminal:other", NULL};
    char *noId[] = {"xpcproxy", NULL};
    char *sshService[] = {"xpcproxy", "com.openssh.sshd", NULL};
    char *wrongService[] = {"xpcproxy", "com.openssh.sshd.fake", NULL};
    if (!rh3_pid1_selected_child("/usr/libexec/xpcproxy",newterm,ssh)) return 1;
    if (!rh3_pid1_selected_child("/usr/libexec/xpcproxy",newtermModern,ssh)) return 25;
    if (rh3_pid1_selected_child("/usr/libexec/xpcproxy",newtermImpostor,ssh)) return 26;
    if (!rh3_pid1_selected_child("/usr/libexec/xpcproxy",sileo,ssh)) return 2;
    if (!rh3_pid1_selected_child("/usr/libexec/xpcproxy",zebra,ssh)) return 3;
    if (!rh3_pid1_selected_child("/usr/libexec/xpcproxy",rootHide,ssh)) return 4;
    if (!rh3_pid1_selected_child("/usr/libexec/xpcproxy",sshService,ssh)) return 5;
    if (!rh3_pid1_selected_child(ssh,NULL,ssh)) return 6;
    if (rh3_pid1_selected_child(NULL,newterm,ssh)) return 7;
    if (rh3_pid1_selected_child("/usr/libexec/xpcproxy",apple,ssh)) return 8;
    if (rh3_pid1_selected_child("/usr/libexec/xpcproxy",fakeId,ssh)) return 9;
    if (rh3_pid1_selected_child("/usr/libexec/xpcproxy",wrongBoundary,ssh)) return 10;
    if (rh3_pid1_selected_child("/usr/libexec/xpcproxy",noId,ssh)) return 11;
    if (rh3_pid1_selected_child("/usr/libexec/xpcproxy",wrongService,ssh)) return 12;
    if (rh3_pid1_selected_child("/tmp/usr/sbin/sshd",NULL,ssh)) return 13;
    if (rh3_pid1_selected_child("/usr/libexec/xpcproxy.evil",newterm,ssh)) return 14;
    if (rh3_pid1_selected_child("/usr/libexec/xpcproxy",newterm,NULL)==0) return 15;
    if (!rh3_pid1_selected_child("/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/Applications/Sileo.app/Sileo",NULL,ssh)) return 16;
    if (!rh3_pid1_selected_child("/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/Applications/Zebra.app/Zebra",NULL,ssh)) return 17;
    if (!rh3_pid1_selected_child("/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/Applications/RootHide.app/RootHide",NULL,ssh)) return 18;
    if (rh3_pid1_selected_child("/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/Applications/NewTerm.app/NewTerm",NULL,ssh)) return 19;
    if (rh3_pid1_selected_child("/var/containers/Bundle/Application/.jbroot-OTHER/Applications/Sileo.app/Sileo",NULL,ssh)) return 20;
    if (rh3_pid1_selected_child("/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/Applications/Sileo.app/Sileo.evil",NULL,ssh)) return 21;
    if (rh3_pid1_selected_child("/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/Applications/Unsafe.app/Unsafe",NULL,ssh)) return 22;
    if (rh3_pid1_selected_child("/Applications/Sileo.app/Sileo",NULL,ssh)) return 23;
    if (!rh3_pid1_selected_child("/private/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/Applications/Sileo.app/Sileo",NULL,ssh)) return 24;
    if (!rh3_pid1_direct_bundle_id("/private/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/Applications/Sileo.app/Sileo",ssh)) return 27;
    if (strcmp(rh3_pid1_direct_bundle_id("/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/Applications/Sileo.app/Sileo",ssh),"org.coolstar.SileoStore")) return 28;
    if (strcmp(rh3_pid1_direct_bundle_id("/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/Applications/Zebra.app/Zebra",ssh),"xyz.willy.Zebra")) return 29;
    if (strcmp(rh3_pid1_direct_bundle_id("/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/Applications/RootHide.app/RootHide",ssh),"com.roothide.manager")) return 30;
    if (rh3_pid1_direct_bundle_id("/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/Applications/NewTerm.app/NewTerm",ssh)) return 31;
    if (rh3_pid1_direct_bundle_id("/var/containers/Bundle/Application/.jbroot-OTHER/Applications/Sileo.app/Sileo",ssh)) return 32;
    if (rh3_pid1_direct_bundle_id("/Applications/Sileo.app/Sileo",ssh)) return 33;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory) / 'selected.c'
            exe = Path(directory) / 'selector_probe.exe'
            src.write_text(source, encoding='utf-8')
            compile_ = subprocess.run([cc, '-std=c11', '-I', str(HEADER.parent),
                                       str(src), '-o', str(exe)], capture_output=True,
                                      text=True, timeout=30)
            self.assertEqual(compile_.returncode, 0, compile_.stderr)
            result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_direct_app_selection_is_bound_to_active_root(self):
        source = HEADER.read_text(encoding='utf-8')
        for fixed in ('/Applications/Sileo.app/Sileo', '/Applications/Zebra.app/Zebra',
                      '/Applications/RootHide.app/RootHide'):
            self.assertIn(fixed, source)
        self.assertIn('rootSshd', source)
        self.assertIn('strcmp(candidate + rootLength,', source)
        self.assertIn('rh3_pid1_direct_bundle_id(', source)
        self.assertNotIn('"/Applications/NewTerm.app/NewTerm"', source,
                         'No locally verified NewTerm executable/blacklist identity')

    def test_rooted_direct_blacklist_precedes_deferred_patch(self):
        source = LAUNCHD.read_text(encoding='utf-8')
        blacklist = source.index('rh3_pid1_direct_bundle_id(path, JBROOT_PATH(')
        lookup = source.index('isBlacklistedApp(directBundleId)', blacklist)
        skip = source.index('roothide_spawn_uninjected(', lookup)
        async_patch = source.index('rh3_pid1_selected_child(path, argv,', lookup)
        self.assertLess(blacklist, lookup)
        self.assertLess(lookup, skip)
        self.assertLess(skip, async_patch)

    def test_pid1_is_never_blocked_on_patch_reply(self):
        src = LAUNCHD.read_text(encoding='utf-8')
        routine = src.split('static int rh3_pid1_spawn_and_patch_async(', 1)[1].split(
            '// launchd commonly spawns UIKit apps', 1)[0]
        self.assertIn('POSIX_SPAWN_START_SUSPENDED', routine)
        self.assertIn('if (!rh3_pid1_has_private_systemhook(envp))', routine)
        self.assertIn('posix_spawnattr_setflags(&attr, flags)', routine)
        self.assertIn('dispatch_async(', routine)
        self.assertIn('dispatch_after(', routine)
        self.assertIn('jbdSpawnPatchChildIdentified(', routine)
        self.assertIn('proc_get_uniqueid(child)', routine)
        self.assertIn('rh3_pid1_outstanding_patches', routine)
        self.assertIn('rh3_pid1_deferred_reserve(&rh3_pid1_outstanding_patches, 4)', routine)
        self.assertIn('rh3_pid1_deferred_finish(&job->outcome, 2)', routine)
        self.assertIn('rh3_pid1_deferred_finish(&job->outcome, 1)', routine)
        self.assertIn('rh3_pid1_kill_failed_child(job)', routine)
        self.assertIn('return 0; // Child is suspended.', routine)
        self.assertLess(routine.index('dispatch_async('), routine.index('return 0; // Child is suspended.'))
        callback = routine.split('dispatch_async(', 1)[1]
        self.assertIn('jbdSpawnPatchChildIdentified', callback)
        # No nested synchronous request in the original PID1 spawn path.
        self.assertNotIn('jbclient_roothide_patch_child(', routine)
        hook = src.split('int __posix_spawn_hook(', 1)[1]
        self.assertLess(hook.index('roothide_blacklisted_uikit_proxy(path, argv)'),
                        hook.index('rh3_pid1_selected_child(path, argv,'))
        for guard in ['roothide_launchdhook_origin_verified()',
                      'jailbreakd_has_checked_in()', '!gInEarlyBoot',
                      '!launchdhookFirstLoad', 'if (!safeMode)']:
            self.assertIn(guard, hook)

    def test_daemon_denies_stale_pid1_requests_before_patch_and_resume(self):
        server = SERVER.read_text(encoding='utf-8')
        handler = server.split('case JBD_MSG_SPAWN_PATCH_CHILD:', 1)[1].split(
            'case JBD_MSG_SPAWN_EXEC_START:', 1)[0]
        self.assertIn('expectedUniqueid && proc_get_uniqueid(pid) == expectedUniqueid', handler)
        self.assertIn('if(ppid == clientPid && sameChild && (!deferredResume', handler)
        self.assertLess(handler.index('if(ppid == clientPid && sameChild && (!deferredResume'),
                        handler.index('roothide_patch_proc(pid)'))
        self.assertIn('proc_get_uniqueid(pid) != expectedUniqueid', handler)
        self.assertLess(handler.index('proc_get_uniqueid(pid) != expectedUniqueid'),
                        handler.index('kill(pid, SIGCONT)'))
        client = CLIENT.read_text(encoding='utf-8').split(
            'int jbdSpawnPatchChildIdentified(', 1)[1].split('int jbdSpinlockFixOnly(', 1)[0]
        self.assertIn('getpid() != 1', client)
        self.assertIn('jailbreakd_has_checked_in()', client)
        self.assertIn('"uniqueid", uniqueid', client)
        self.assertIn('xpc_get_type(value) == XPC_TYPE_INT64', client)

    def test_watchdog_wins_without_daemon_late_resume(self):
        source = LAUNCHD.read_text(encoding='utf-8')
        worker = source.split('dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{', 1)[1].split('return 0; // Child is suspended.', 1)[0]
        # The prior implementation set resume=true in the daemon request.
        # A slow daemon could then send SIGCONT AFTER the PID1 timeout won.
        self.assertIn('jbdSpawnPatchChildIdentified(job->pid, job->uniqueid)', worker)
        self.assertNotIn('jbdSpawnPatchChildIdentified(job->pid, job->uniqueid, true)', worker)
        self.assertIn('if (patched == 0 && rh3_pid1_deferred_finish(&job->outcome, 1))', worker)
        self.assertIn('kill(job->pid, SIGCONT)', worker)
        client = CLIENT.read_text(encoding='utf-8').split('int jbdSpawnPatchChildIdentified(', 1)[1].split('int jbdSpinlockFixOnly(', 1)[0]
        self.assertIn('"deferred_resume", true', client)
        self.assertIn('"resume", false', client)
        server = SERVER.read_text(encoding='utf-8').split('case JBD_MSG_SPAWN_PATCH_CHILD:',1)[1].split('case JBD_MSG_SPAWN_EXEC_START:',1)[0]
        self.assertIn('bool deferredResume = xpc_dictionary_get_bool(message, "deferred_resume")', server)
        self.assertIn('&& !deferredResume', server)
        self.assertIn('else if(resume && !deferredResume && kill(pid, SIGCONT)', server)

    def test_native_actual_state_handles_races_backpressure_and_recovery(self):
        cc = shutil.which('gcc') or shutil.which('clang') or shutil.which('cc')
        if not cc:
            self.skipTest('C compiler unavailable')
        source = r'''
#include "roothide_pid1_deferred_state.h"
int main(void) {
    _Atomic int state=0;
    if (!rh3_pid1_deferred_finish(&state, 1)) return 1;
    if (rh3_pid1_deferred_finish(&state, 2)) return 2;
    if (atomic_load(&state) != 1) return 3;
    atomic_store(&state,0);
    if (!rh3_pid1_deferred_finish(&state,2)) return 4;
    if (rh3_pid1_deferred_finish(&state,1)) return 5;
    if (atomic_load(&state) != 2) return 6;
    _Atomic int outstanding=0;
    for (int i=0;i<4;i++)
        if (!rh3_pid1_deferred_reserve(&outstanding,4)) return 7;
    if (rh3_pid1_deferred_reserve(&outstanding,4)) return 8;
    atomic_fetch_sub(&outstanding,1);
    if (!rh3_pid1_deferred_reserve(&outstanding,4)) return 9;
    if (atomic_load(&outstanding)!=4) return 10;
    if (rh3_pid1_deferred_finish(&state,0)) return 11;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'state.c'
            exe = Path(directory) / 'state_probe.exe'
            file.write_text(source, encoding='utf-8')
            build = subprocess.run([cc, '-std=c11', '-I', str(STATE.parent),
                                    str(file), '-o', str(exe)], capture_output=True,
                                   text=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == '__main__':
    unittest.main()
