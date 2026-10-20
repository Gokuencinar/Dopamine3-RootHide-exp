"""Execute the production spawn helper with fake OS calls; no iOS simulation."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InternalSpawnTests(unittest.TestCase):
    def test_bootstrap_commands_use_helper_only_for_an_active_hidden_root(self):
        util = (ROOT/'BaseBin/libjailbreak/src/util.c').read_text()
        section = util.split('int __exec_cmd_internal_va', 1)[1].split('int exec_cmd(', 1)[0]
        self.assertIn('roothide_is_active()', section)
        self.assertIn('? exec_cmd_roothide_spawn(', section)
        self.assertIn(': posix_spawn(', section)
        jb = (ROOT/'Application/Dopamine/Jailbreak/DOJailbreaker.m').read_text()
        entry = jb.split('- (void)runWithError:', 1)[1]
        self.assertLess(entry.index('exec_set_patch(false)'), entry.index('[self doExploitation]'))
        self.assertLess(entry.index('ensure_dyld_trustcache('), entry.index('exec_set_patch(true)'))

    def test_native_helper_flags_trust_cleanup_and_failure_paths(self):
        compiler = shutil.which('cc') or shutil.which('clang') or shutil.which('gcc')
        if not compiler:
            self.skipTest('No native C compiler')
        source = (ROOT/'BaseBin/libjailbreak/src/roothider/common.m').read_text()
        function = source[source.index('int exec_cmd_roothide_spawn_traced('):source.index('\nint ensure_dyld_trustcache(')]
        self.assertIn('jbclient_roothide_patch_child(pid, should_resume)', function)
        self.assertIn('jbclient_roothide_patch_child_traced(pid, should_resume, callback, context)', function)
        self.assertNotIn('jbdSpawnPatchChild(', function)
        self.assertIn('callback("posix_spawn entering"', function)
        self.assertIn('callback("posix_spawn returned"', function)
        self.assertIn('callback("patch child XPC entering"', function)
        self.assertIn('callback("patch child XPC returned"', function)
        harness = r'''
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
typedef void (*rh3_spawn_stage_callback_t)(const char *stage, int pid, int result, void *context);
typedef int pid_t;
typedef struct attrs { short flags; } *posix_spawnattr_t;
typedef void posix_spawn_file_actions_t;
#define POSIX_SPAWN_START_SUSPENDED 128
#define SIGCONT 19
#define SIGKILL 9
#ifndef WNOHANG
#define WNOHANG 1
#endif
#define RTLD_NOLOAD 16
#define RTLD_LAZY 1
#define JBROOT_PATH(x) x
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)
// macOS stdlib.h also declares waitpid. Keep fake calls distinct from host
// libc; the production function below is redirected by these macros too.
#define waitpid rh_test_waitpid
#define getpid rh_test_getpid
#define kill rh_test_kill
#define usleep rh_test_usleep
#define dlopen rh_test_dlopen
#define dlclose rh_test_dlclose
static bool exec_patch_enabled;
static struct { int hook, close, trust_error, trust_calls, init_error, read_error,
    spawn_error, patch_error, resume_error, init, destroy, spawn, patch, resume,
    killed, waited, should_resume, seen_flags; } state;
static char stages[16][48]; static int stage_count;
static void capture(const char *stage,int pid,int result,void *context) {
    if(stage_count < 16) snprintf(stages[stage_count++],48,"%s",stage);
}
static void reset(void) { memset(&state, 0, sizeof(state)); exec_patch_enabled=true; }
static void *dlopen(const char *p, int mode) { return state.hook ? (void *)1 : NULL; }
static int dlclose(void *p) { state.close++; return 0; }
static bool dyld_patch_enabled(void) { return false; }
static pid_t getpid(void) { return 123; }
static int jbclient_trust_executable_recurse(const char *p, void *a) { state.trust_calls++; return state.trust_error; }
static int posix_spawnattr_init(posix_spawnattr_t *a) { state.init++; if(state.init_error) return state.init_error; *a=calloc(1,sizeof(**a)); return *a ? 0 : ENOMEM; }
static int posix_spawnattr_destroy(posix_spawnattr_t *a) { state.destroy++; free(*a); *a=NULL; return 0; }
static int posix_spawnattr_getflags(const posix_spawnattr_t *a, short *f) { *f=(*a)->flags; return state.read_error; }
static int posix_spawnattr_setflags(const posix_spawnattr_t *a, short f) { (*a)->flags=f; return 0; }
static int posix_spawn(pid_t *pid, const char *path, const void *fa, const posix_spawnattr_t *a, char *const argv[], char *const env[]) {
    state.spawn++; state.seen_flags=(*a)->flags; if(!state.spawn_error) *pid=42; return state.spawn_error;
}
static int jbclient_roothide_patch_child(pid_t p, bool resume) { state.patch++; state.should_resume=resume; return state.patch_error; }
static int jbclient_roothide_patch_child_traced(pid_t p, bool resume,
        void (*checkpoint)(const char *, pid_t, int, void *), void *context) {
    checkpoint("jailbreakd lookup entering",p,0,context);
    checkpoint("jailbreakd lookup returned",p,0,context);
    checkpoint("jailbreakd request entering",p,0,context);
    int result=jbclient_roothide_patch_child(p,resume);
    checkpoint("jailbreakd request returned",p,result,context);
    return result;
}
static int kill(pid_t p, int s) { if(s==SIGKILL) state.killed++; else if(s==SIGCONT) { state.resume++; if(state.resume_error) { errno=EPERM; return -1; } } return 0; }
static pid_t waitpid(pid_t p, int *s, int options) { state.waited++; return p; }
static int usleep(unsigned x) { return 0; }
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"line %d: %s\n", __LINE__, #x); return 1; } } while(0)
'''
        cases = r'''
int main(void) {
    char *args[]={(char *)"/tool",NULL}; pid_t pid=99;
    struct attrs external={0}; posix_spawnattr_t attr=&external;
    reset(); stage_count=0;
    CHECK(exec_cmd_roothide_spawn_traced(&pid,"/tool",NULL,&attr,args,NULL,capture,NULL)==0);
    CHECK(stage_count==8);
    CHECK(strcmp(stages[0],"posix_spawn entering")==0);
    CHECK(strcmp(stages[1],"posix_spawn returned")==0);
    CHECK(strcmp(stages[2],"patch child XPC entering")==0);
    CHECK(strcmp(stages[3],"jailbreakd lookup entering")==0);
    CHECK(strcmp(stages[4],"jailbreakd lookup returned")==0);
    CHECK(strcmp(stages[5],"jailbreakd request entering")==0);
    CHECK(strcmp(stages[6],"jailbreakd request returned")==0);
    CHECK(strcmp(stages[7],"patch child XPC returned")==0);
    reset(); exec_patch_enabled=false;
    CHECK(exec_cmd_roothide_spawn(&pid,"/tool",NULL,&attr,args,NULL)==0);
    CHECK(pid==42 && state.patch==0 && state.trust_calls==0 && state.resume==1);
    CHECK(external.flags==0 && state.seen_flags==POSIX_SPAWN_START_SUSPENDED);
    reset(); exec_patch_enabled=false; external.flags=POSIX_SPAWN_START_SUSPENDED;
    CHECK(exec_cmd_roothide_spawn(&pid,"/tool",NULL,&attr,args,NULL)==0);
    CHECK(state.resume==0 && external.flags==POSIX_SPAWN_START_SUSPENDED);
    external.flags=0;
    reset(); state.patch_error=7;
    CHECK(exec_cmd_roothide_spawn(&pid,"/tool",NULL,&attr,args,NULL)==202);
    CHECK(pid==0 && state.killed==1 && state.waited==1 && state.trust_calls==1 && external.flags==0);
    reset(); state.trust_error=1; pid=99;
    CHECK(exec_cmd_roothide_spawn(&pid,"/tool",NULL,NULL,args,NULL)==999);
    CHECK(pid==0 && state.spawn==0 && state.init==0);
    reset(); state.init_error=EINVAL;
    CHECK(exec_cmd_roothide_spawn(&pid,"/tool",NULL,NULL,args,NULL)==EINVAL);
    CHECK(state.spawn==0 && state.destroy==0);
    reset();
    CHECK(exec_cmd_roothide_spawn(&pid,"/tool",NULL,NULL,args,NULL)==0);
    CHECK(pid==42 && state.patch==1 && state.should_resume && state.resume==0 && state.destroy==1);
    reset(); state.hook=1;
    CHECK(exec_cmd_roothide_spawn(&pid,"/tool",NULL,NULL,args,NULL)==0);
    CHECK(state.close==1 && state.patch==0 && state.trust_calls==0 && state.resume==1 && state.destroy==1);
    reset(); state.spawn_error=ENOENT;
    CHECK(exec_cmd_roothide_spawn(&pid,"/tool",NULL,&attr,args,NULL)==ENOENT);
    CHECK(external.flags==0 && state.killed==0 && pid==0);
    reset(); state.read_error=EINVAL;
    CHECK(exec_cmd_roothide_spawn(&pid,"/tool",NULL,NULL,args,NULL)==EINVAL);
    CHECK(state.destroy==1 && state.spawn==0);
    reset(); exec_patch_enabled=false; state.resume_error=1;
    CHECK(exec_cmd_roothide_spawn(&pid,"/tool",NULL,NULL,args,NULL)==EPERM);
    CHECK(state.killed==1 && state.waited==1 && state.destroy==1 && pid==0);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'helper.c'
            executable = Path(directory)/'helper.exe'
            path.write_text(harness + function + cases)
            build = subprocess.run([compiler, '-std=c11', str(path), '-o', str(executable)], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
