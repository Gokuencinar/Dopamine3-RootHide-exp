"""Execute the actual PID 1 RootHide spawn environment branch with fake OS calls.

This runs on a workstation; it cannot prove launchd, dyld, trustcache, or
sshd behavior on iOS. It checks the production helper and wrapper together.
"""
from pathlib import Path
import shutil
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "BaseBin/launchdhook/src/spawn_hook.c"
MANAGER = ROOT / "BaseBin/launchdhook/src/roothide_manager_spawn.h"


class PID1PrivateDyldTests(unittest.TestCase):
    def test_early_boot_null_path_and_failed_manager_spawn_are_bounded(self):
        text = SOURCE.read_text(encoding="utf-8")
        hook = text.split("int __posix_spawn_hook(pid_t", 1)[1]
        self.assertIn('if (path && !strcmp(path, "/usr/libexec/xpcproxy"))', hook)
        self.assertIn('if (argv && argv[0])', hook)
        wrapper = text.split('int __posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path,', 2)[-1].split(
            '// launchd commonly spawns UIKit apps through xpcproxy', 1)[0]
        self.assertIn('r, r == 0 ? *recordedPid : 0', wrapper)

    def test_bounded_pid1_private_dyld_contract(self):
        compiler = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
        if not compiler:
            self.skipTest("No native C compiler")
        text = SOURCE.read_text(encoding="utf-8")
        functions = text[text.index("static const char *rh3_pid1_var_alias_n("):
                         text.index("// launchd commonly spawns UIKit apps")]
        # Production origin verifier is exercised by its own mocked-dladdr
        # test. This older harness intentionally supplies a forced origin
        # result; skip unrelated real PID1 origin and fakelib implementation.
        functions = re.sub(
            r"bool roothide_launchdhook_origin_verified\(void\)\s*\{.*?\n\}\s*",
            "", functions, count=1, flags=re.S)
        functions = re.sub(
            r"void ensure_fakelib_mounted\(void\)\s*\{.*?\n\}\s*",
            "", functions, count=1, flags=re.S)
        self.assertNotIn("jbdSpawnPatchChild", functions)
        self.assertNotIn("jailbreakdXpcRequest", functions)
        self.assertNotIn("POSIX_SPAWN_START_SUSPENDED", functions)
        self.assertIn("__posix_spawn_inline(recordedPid", functions)
        self.assertIn("register_job(*recordedPid)", functions)
        manager_helper = MANAGER.read_text(encoding="utf-8")
        harness = r'''
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
typedef int pid_t;
typedef struct { short flags; int type; int flag_error; } fake_attr;
typedef fake_attr *posix_spawnattr_t;
struct _posix_spawn_args_desc { posix_spawnattr_t attrp; };
#define POSIX_SPAWN_SETEXEC 64
#define POSIX_SPAWN_PROC_TYPE_DRIVER 1792
#define PATH_MAX 4096
#define getpid test_getpid
#define JBROOT_PATH(path) test_jbroot_path(path)
static int test_pid=1, test_active=1, test_origin=1;
static bool gInEarlyBoot=false, launchdhookFirstLoad=false;
static int spawn_calls, registrations, pauses, resumes, spawn_error;
static pid_t last_registered, pid_from_kernel;
static int force_alloc_failure, alloc_count;
static char seen[24][512];
static int seen_count;
static char root[]="/private/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF";
static char path[PATH_MAX];
static char inserted[PATH_MAX];
static const char *get_jbroot(void) { return root; }
static int test_getpid(void) { return test_pid; }
static bool roothide_is_active(void) { return test_active; }
static bool roothide_launchdhook_origin_verified(void) { return test_origin; }
static char *test_jbroot_path(const char *suffix) {
    static char buffer[PATH_MAX];
    snprintf(buffer,sizeof(buffer),"%s%s",root,suffix);
    return buffer;
}
'''+manager_helper+r'''
static char manager_stage[200];
static void rh3_bootlog(const char *line) {
    if (!strncmp(line,"manager launch",14) && strstr(line,"systemhook_insert="))
        snprintf(manager_stage,sizeof(manager_stage),"%s",line);
}
static int posix_spawnattr_getflags(const posix_spawnattr_t *a,short *flags) {
    if ((*a)->flag_error) return (*a)->flag_error;
    *flags=(*a)->flags; return 0;
}
static int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t *a,int *type) {
    *type=(*a)->type; return 0;
}
static void *rh3_test_calloc(size_t count,size_t item) {
    alloc_count++;
    if (force_alloc_failure) return NULL;
    return calloc(count,item);
}
#define calloc rh3_test_calloc
static void crashreporter_pause(void) { pauses++; }
static void crashreporter_resume(void) { resumes++; }
static void register_job(pid_t pid) { registrations++; last_registered=pid; }
static int __posix_spawn_inline(pid_t *pid,const char *p,
        struct _posix_spawn_args_desc *d,char *const a[],char *const e[]) {
    (void)p;(void)d;(void)a;
    spawn_calls++; seen_count=0;
    for (int i=0;e && e[i] && i<24;i++) {
        snprintf(seen[seen_count++],sizeof(seen[0]),"%s",e[i]);
    }
    if (spawn_error) return spawn_error;
    *pid=712;
    pid_from_kernel=*pid;
    return 0;
}
static bool has(const char *v) {
    for(int i=0;i<seen_count;i++) if(!strcmp(seen[i],v))return true;
    return false;
}
static int prefix_count(const char *p) {
    int n=0;
    for(int i=0;i<seen_count;i++) if(!strncmp(seen[i],p,strlen(p)))n++;
    return n;
}
static void reset(void) {
    test_pid=1; test_active=1; test_origin=1;
    gInEarlyBoot=false; launchdhookFirstLoad=false;
    spawn_calls=registrations=pauses=resumes=spawn_error=0;
    alloc_count=force_alloc_failure=0;
    last_registered=pid_from_kernel=0;
    seen_count=0;
    manager_stage[0]='\0';
    snprintf(path,sizeof(path),"%s/usr/sbin/sshd",root);
    snprintf(inserted,sizeof(inserted),"DYLD_INSERT_LIBRARIES=%s/basebin/systemhook.dylib",root);
}
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"line %d: %s\n",__LINE__,#c); return 1; } } while(0)
'''
        cases = r'''
int main(void) {
    fake_attr attr={0}; struct _posix_spawn_args_desc desc={&attr};
    char *args[]={"sshd",NULL};
    char *env[]={inserted,"OTHER=kept","DYLD_IN_CACHE=1","DYLD_IN_CACHE=5",NULL};
    pid_t pid=0;
    reset();
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,env)==0);
    CHECK(pid==712 && registrations==1 && last_registered==712);
    CHECK(has("OTHER=kept") && has("DYLD_IN_CACHE=0"));
    CHECK(prefix_count("DYLD_IN_CACHE=")==1);
    CHECK(!strcmp(env[2],"DYLD_IN_CACHE=1") && !strcmp(env[3],"DYLD_IN_CACHE=5"));
    CHECK(alloc_count==1 && pauses==1 && resumes==1);

    reset(); char *zero[]={inserted,"DYLD_IN_CACHE=0",NULL};
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,zero)==0);
    CHECK(alloc_count==0 && has("DYLD_IN_CACHE=0"));
    reset(); char *missing[]={inserted,"OTHER=kept",NULL};
    CHECK(__posix_spawn_orig_wrapper(NULL,path,&desc,args,missing)==0);
    CHECK(alloc_count==1 && has("DYLD_IN_CACHE=0") && registrations==1);

    reset(); snprintf(path,sizeof(path),"%s/usr/bin/login",root);
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(has("DYLD_IN_CACHE=0"));
    reset(); snprintf(path,sizeof(path),"%s/bin/login",root);
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(has("DYLD_IN_CACHE=0"));
    // Both paths name the same active root on iOS; do not skip private dyld
    // because launchd uses /var while get_jbroot is /private/var.
    reset(); snprintf(path,sizeof(path),"%s/usr/sbin/sshd",root+8);
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(has("DYLD_IN_CACHE=0"));
    reset(); snprintf(path,sizeof(path),"%s/usr/sbin/sshd",root);
    char alternateInsert[PATH_MAX+64];
    snprintf(alternateInsert,sizeof(alternateInsert),
             "DYLD_INSERT_LIBRARIES=%s/basebin/systemhook.dylib",root+8);
    char *alternateEnv[]={alternateInsert,"OTHER=kept",NULL};
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,alternateEnv)==0);
    CHECK(has("DYLD_IN_CACHE=0") && has("OTHER=kept"));
    reset(); snprintf(path,sizeof(path),"%s/usr/sbin/sshd",root);
    char *wrongBrand[]={"DYLD_INSERT_LIBRARIES=/var/containers/Bundle/Application/.jbroot-AAAAAAAAAAAAAAAA/basebin/systemhook.dylib",NULL};
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,wrongBrand)==0);
    CHECK(!has("DYLD_IN_CACHE=0"));
    const char *direct[]={"/Applications/Sileo.app/Sileo","/Applications/Zebra.app/Zebra",
                          "/Applications/RootHide.app/RootHide"};
    for(int i=0;i<3;i++) {
        reset(); snprintf(path,sizeof(path),"%s%s",root,direct[i]);
        CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
        CHECK(has("DYLD_IN_CACHE=0"));
    }

    reset(); strcpy(path,"/usr/libexec/xpcproxy");
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(!has("DYLD_IN_CACHE=0") && alloc_count==0);
    const char *managerLabels[]={"UIKitApplication:xyz.willy.Zebra[0x1]",
        "UIKitApplication:org.coolstar.SileoStore[0x2]",
        "UIKitApplication:com.roothide.manager[0x3]"};
    for(int i=0;i<3;i++) {
        reset(); strcpy(path,"/usr/libexec/xpcproxy");
        char *proxyArgs[]={"xpcproxy",(char*)managerLabels[i],NULL};
        CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,proxyArgs,missing)==0);
        CHECK(has("DYLD_IN_CACHE=0") && registrations==1);
        CHECK(strstr(manager_stage,"systemhook_insert=1")!=NULL);
    }
    reset(); strcpy(path,"/usr/libexec/xpcproxy");
    char *zebraProxy[]={"xpcproxy","UIKitApplication:xyz.willy.Zebra[0x1]",NULL};
    char *spoofedHook[]={"DYLD_INSERT_LIBRARIES=/evil/systemhook.dylib",NULL};
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,zebraProxy,spoofedHook)==0);
    CHECK(strstr(manager_stage,"systemhook_insert=0")!=NULL);
    CHECK(!has("DYLD_IN_CACHE=0"));
    reset(); strcpy(path,"/usr/libexec/xpcproxy");
    char *notManager[]={"xpcproxy","UIKitApplication:com.apple.Preferences[0x1]",NULL};
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,notManager,missing)==0);
    CHECK(!has("DYLD_IN_CACHE=0") && alloc_count==0);
    char *spoof[]={"xpcproxy","UIKitApplication:xyz.willy.Zebra.extra[0x1]",NULL};
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,spoof,missing)==0);
    CHECK(!has("DYLD_IN_CACHE=0") && alloc_count==0);
    char *malformed[]={"xpcproxy","xyz.willy.Zebra[0x1]",NULL};
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,malformed,missing)==0);
    CHECK(!has("DYLD_IN_CACHE=0") && alloc_count==0);
    reset(); strcpy(path,"/usr/sbin/sshd");
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(!has("DYLD_IN_CACHE=0"));
    reset(); snprintf(path,sizeof(path),"%s-copy/usr/sbin/sshd",root);
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(!has("DYLD_IN_CACHE=0"));
    reset(); snprintf(path,sizeof(path),"%s/usr/sbin/sshd-malicious",root);
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(!has("DYLD_IN_CACHE=0"));

    reset(); test_pid=2;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(alloc_count==0);
    reset(); test_origin=0;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(alloc_count==0);
    reset(); test_active=0;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(alloc_count==0 && registrations==0);
    reset(); launchdhookFirstLoad=true;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(alloc_count==0);
    reset(); gInEarlyBoot=true;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(alloc_count==0);

    reset(); attr.flags=POSIX_SPAWN_SETEXEC;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(alloc_count==0 && attr.flags==POSIX_SPAWN_SETEXEC);
    reset(); attr.flags=0; attr.type=POSIX_SPAWN_PROC_TYPE_DRIVER;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(alloc_count==0);
    reset(); attr.type=0; attr.flag_error=EINVAL;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(alloc_count==0);
    reset(); attr.flag_error=0;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,NULL,args,missing)==0);
    CHECK(alloc_count==1 && has("DYLD_IN_CACHE=0"));
    reset(); desc.attrp=NULL;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==0);
    CHECK(alloc_count==1 && has("DYLD_IN_CACHE=0"));
    desc.attrp=&attr;
    reset(); strcpy(path,"/usr/libexec/xpcproxy");
    CHECK(__posix_spawn_orig_wrapper(&pid,path,NULL,args,missing)==0);
    CHECK(alloc_count==0 && !has("DYLD_IN_CACHE=0"));

    reset(); char *wrong[]={"DYLD_INSERT_LIBRARIES=/old/basebin/systemhook.dylib",NULL};
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,wrong)==0);
    CHECK(alloc_count==0);
    reset(); char *suffix[]={"DYLD_INSERT_LIBRARIES=/evil/basebin/systemhook.dylib",NULL};
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,suffix)==0);
    CHECK(alloc_count==0);
    reset(); char *colon[]={"DYLD_INSERT_LIBRARIES=",NULL};
    char combo[PATH_MAX+99];
    snprintf(combo,sizeof(combo),"DYLD_INSERT_LIBRARIES=/third.dylib:%s/basebin/systemhook.dylib",root);
    colon[0]=combo;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,colon)==0);
    CHECK(has("DYLD_IN_CACHE=0"));

    reset(); force_alloc_failure=1;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==ENOMEM);
    CHECK(spawn_calls==0 && registrations==0 && pauses==0);
    reset(); char *oversized[4099];
    oversized[0]=inserted;
    for(int i=1;i<4097;i++) oversized[i]="OTHER=kept";
    oversized[4097]=NULL;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,oversized)==E2BIG);
    CHECK(spawn_calls==0 && registrations==0 && pauses==0);
    reset(); spawn_error=ENOENT;
    CHECK(__posix_spawn_orig_wrapper(&pid,path,&desc,args,missing)==ENOENT);
    CHECK(registrations==0 && pauses==1 && resumes==1);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "pid1_r173.c"
            binary = Path(tmp) / "pid1_r173.exe"
            source.write_text(harness + functions + cases, encoding="utf-8")
            build = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra",
                                    str(source), "-o", str(binary)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(binary)], capture_output=True,
                                    text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
