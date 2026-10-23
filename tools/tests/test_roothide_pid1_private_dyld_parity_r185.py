"""Run the production launchd private-dyld policy under mocked PID 1 state.

This is a host C test, not evidence of iOS kernel patching or a working SSH banner.
It deliberately covers the service processes omitted by the old manager whitelist.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "BaseBin/launchdhook/src/spawn_hook.c"
MANAGER = ROOT / "BaseBin/launchdhook/src/roothide_manager_spawn.h"


class PID1PrivateDyldParityR185(unittest.TestCase):
    def test_no_launchd_self_xpc_or_implicit_suspend_for_private_dyld(self):
        source = SOURCE.read_text(encoding="utf-8")
        helper = source.split("// RootHide 2 used private dyld mappings", 1)[1].split(
            "int __posix_spawn_orig_wrapper(pid_t", 1
        )[0]
        for forbidden in ("jbdSpawnPatchChild(", "jbclient_roothide_patch_child(",
                          "xpc_pipe_routine(", "jbserver_xpc_send(",
                          "POSIX_SPAWN_START_SUSPENDED", "kill(", "waitpid("):
            self.assertNotIn(forbidden, helper)
        self.assertIn("rh3_pid1_has_private_systemhook(envp)", helper)
        self.assertIn("roothide_launchdhook_origin_verified()", helper)

    def test_real_c_private_dyld_policy_for_all_verified_injected_children(self):
        compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not compiler:
            self.skipTest("Native C compiler unavailable")
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("// RootHide 2 used private dyld mappings")
        functions = source[start:source.index("int __posix_spawn_orig_wrapper(pid_t", start)]
        # The old implementation uses this for a restrictive manager whitelist.
        manager = MANAGER.read_text(encoding="utf-8")
        harness = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define PATH_MAX 4096
#define POSIX_SPAWN_SETEXEC 0x40
#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
typedef struct { short flags; int type; int flag_error; } fake_attr;
typedef fake_attr *posix_spawnattr_t;
struct _posix_spawn_args_desc { posix_spawnattr_t attrp; };
static bool gInEarlyBoot=false, launchdhookFirstLoad=false;
static int fake_pid=1, fake_active=1, fake_origin=1;
static const char root[]="/private/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF";
static char hook[PATH_MAX], alternate_hook[PATH_MAX];
static int allocations;
#define getpid test_pid
#define JBROOT_PATH(path) test_root_path(path)
static int test_pid(void) { return fake_pid; }
static bool roothide_is_active(void) { return fake_active; }
static bool roothide_launchdhook_origin_verified(void) { return fake_origin; }
static const char *get_jbroot(void) { return root; }
static char *test_root_path(const char *suffix) {
    static char path[PATH_MAX];
    snprintf(path,sizeof(path),"%s%s",root,suffix);
    return path;
}
static int posix_spawnattr_getflags(const posix_spawnattr_t *a,short *out) {
    if ((*a)->flag_error) return (*a)->flag_error;
    *out=(*a)->flags; return 0;
}
static int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t *a,int *out) {
    *out=(*a)->type; return 0;
}
static void *test_calloc(size_t n,size_t size) {
    allocations++; return calloc(n,size);
}
#define calloc test_calloc
'''+manager+r'''
'''
        cases = r'''
#define REQUIRE(value) do { if(!(value)) { \
    fprintf(stderr,"assert line %d: %s\n",__LINE__,#value); return 1; } } while(0)
static int env_count(char *const env[], const char *name) {
    int result=0; size_t n=strlen(name);
    for(int i=0; env && env[i]; i++) if(!strncmp(env[i],name,n))result++;
    return result;
}
static bool has(char *const env[],const char *value) {
    for(int i=0; env && env[i];i++) if(!strcmp(env[i],value)) return true;
    return false;
}
static int check(const char *path, struct _posix_spawn_args_desc *desc,
                 char *const env[], bool expected) {
    char **owned=(char**)0x1;
    int before=allocations;
    int result=rh3_pid1_prepare_private_dyld_env(path,NULL,desc,env,&owned);
    REQUIRE(result==0);
    if(expected) {
        REQUIRE(owned != NULL);
        REQUIRE(allocations==before+1);
        REQUIRE(has(owned,"DYLD_IN_CACHE=0"));
        REQUIRE(has(owned,"OTHER=kept"));
        REQUIRE(env_count(owned,"DYLD_IN_CACHE=")==1);
        free(owned);
    } else {
        REQUIRE(owned==NULL);
        REQUIRE(allocations==before);
    }
    return 0;
}
int main(void) {
    snprintf(hook,sizeof(hook),"DYLD_INSERT_LIBRARIES=%s/basebin/systemhook.dylib",root);
    snprintf(alternate_hook,sizeof(alternate_hook),
        "DYLD_INSERT_LIBRARIES=%s/basebin/systemhook.dylib",root+8);
    char *injected[]={hook,"DYLD_IN_CACHE=1","OTHER=kept","DYLD_IN_CACHE=7",NULL};
    fake_attr attr={0}; struct _posix_spawn_args_desc desc={&attr};
    // Donor parity: the chosen *active-root* hook requires private dyld,
    // irrespective of whether the launched binary is inside .jbroot.
    const char *services[]={"/usr/libexec/lsd", "/usr/sbin/cfprefsd",
        "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
        "/usr/libexec/xpcproxy", "/usr/libexec/amfid",
        "/usr/sbin/sshd", NULL};
    for(int i=0;services[i];i++) REQUIRE(check(services[i],&desc,injected,true)==0);
    REQUIRE(!strcmp(injected[1],"DYLD_IN_CACHE=1"));
    char *alias[]={alternate_hook,"OTHER=kept",NULL};
    REQUIRE(check("/usr/libexec/lsd",&desc,alias,true)==0);
    char *wrong[]={"DYLD_INSERT_LIBRARIES=/evil/basebin/systemhook.dylib","OTHER=kept",NULL};
    REQUIRE(check("/usr/libexec/lsd",&desc,wrong,false)==0);
    char *prefix[]={"DYLD_INSERT_LIBRARIES=/bad/basebin/systemhook.dylib:/evil.so","OTHER=kept",NULL};
    REQUIRE(check("/usr/libexec/lsd",&desc,prefix,false)==0);
    char *combo[3]={"DYLD_INSERT_LIBRARIES=/thirdparty.dylib","OTHER=kept",NULL};
    char entry[PATH_MAX+32];
    snprintf(entry,sizeof(entry),"DYLD_INSERT_LIBRARIES=/thirdparty.dylib:%s/basebin/systemhook.dylib",root);
    combo[0]=entry;
    REQUIRE(check("/usr/libexec/lsd",&desc,combo,true)==0);
    char *zero[]={hook,"DYLD_IN_CACHE=0","OTHER=kept",NULL};
    REQUIRE(check("/usr/libexec/lsd",&desc,zero,false)==0);
    REQUIRE(check(NULL,&desc,injected,false)==0);
    fake_pid=12; REQUIRE(check("/usr/libexec/lsd",&desc,injected,false)==0); fake_pid=1;
    fake_active=0; REQUIRE(check("/usr/libexec/lsd",&desc,injected,false)==0); fake_active=1;
    fake_origin=0; REQUIRE(check("/usr/libexec/lsd",&desc,injected,false)==0); fake_origin=1;
    gInEarlyBoot=true; REQUIRE(check("/usr/libexec/lsd",&desc,injected,false)==0); gInEarlyBoot=false;
    launchdhookFirstLoad=true;
    REQUIRE(check("/usr/libexec/lsd",&desc,injected,false)==0);
    launchdhookFirstLoad=false;
    attr.flags=POSIX_SPAWN_SETEXEC;
    REQUIRE(check("/usr/libexec/lsd",&desc,injected,false)==0); attr.flags=0;
    attr.type=POSIX_SPAWN_PROC_TYPE_DRIVER;
    REQUIRE(check("/usr/libexec/lsd",&desc,injected,false)==0); attr.type=0;
    attr.flag_error=EINVAL;
    REQUIRE(check("/usr/libexec/lsd",&desc,injected,false)==0); attr.flag_error=0;
    REQUIRE(check("/usr/libexec/lsd",NULL,injected,true)==0);
    REQUIRE(check("/usr/libexec/lsd",&desc,NULL,false)==0);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pid1_parity.c"
            executable = Path(tmp) / "pid1_parity.exe"
            path.write_text(harness + functions + cases, encoding="utf-8")
            build = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra",
                                    str(path), "-o", str(executable)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=12)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
