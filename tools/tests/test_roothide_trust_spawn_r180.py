"""C-executed RootHide trust/spawn policy and entrypoint source contracts."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "BaseBin/systemhook/src/common/roothide_trust_policy.h"
MAIN = ROOT / "BaseBin/systemhook/src/main.c"


class TrustSpawnPolicyTests(unittest.TestCase):
    def test_native_magic_detects_macho_and_excludes_scripts(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("No host C compiler")
        code = r'''
#include "roothide_trust_policy.h"
int main(int argc,char **argv) {
    if (argc != 4) return 9;
    return rh3_trust_looks_like_macho(argv[1]) &&
           !rh3_trust_looks_like_macho(argv[2]) &&
           !rh3_trust_looks_like_macho(argv[3]) ? 0 : 1;
}
'''
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            native = tmp / "native"
            native.write_bytes(bytes.fromhex("cffaedfe") + b"\0" * 40)
            script = tmp / "script"
            script.write_bytes(b"#!/bin/sh\necho ok\n")
            short = tmp / "short"
            short.write_bytes(b"abc")
            src = tmp / "magic.c"
            exe = tmp / "magic.exe"
            src.write_text(code, encoding="utf-8")
            build = subprocess.run([cc, "-std=c11", "-I", str(HEADER.parent), str(src),
                                    "-o", str(exe)], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(exe), str(native), str(script), str(short)],
                                 capture_output=True, text=True, timeout=8)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_native_arch_preferences_use_the_actual_bounded_builder(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("No host C compiler")
        source = MAIN.read_text(encoding="utf-8")
        fn = source[source.index("static xpc_object_t rh3_copy_spawn_arch_preferences("):
                    source.index("static int rh3_trust_before_spawn(")]
        prelude = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#define XPC_ARRAY_APPEND ((size_t)-1)
typedef int cpu_type_t;
typedef int cpu_subtype_t;
typedef void *xpc_object_t;
typedef struct {int dummy;} *posix_spawnattr_t;
struct _posix_spawn_args_desc {posix_spawnattr_t attrp;};
static int count_requested, getter_error, set_calls, array_calls, released;
static size_t getter_count=2;
static int requested_types[4]={12,13,0,0};
static int requested_subtypes[4]={2,3,-1,-1};
static struct {unsigned long type,subtype;} captured[4];
static int posix_spawnattr_getarchpref_np(posix_spawnattr_t *attrs,size_t cap,
    cpu_type_t *types,cpu_subtype_t *subs,size_t *count) {
    (void)attrs;count_requested++;
    if (getter_error) return getter_error;
    *count=getter_count;
    for(size_t i=0;i<getter_count && i<cap;i++) {
        types[i]=requested_types[i];subs[i]=requested_subtypes[i];
    }
    return 0;
}
static int fake_array, fake_dict;
static xpc_object_t xpc_array_create_empty(void){array_calls++;return &fake_array;}
static xpc_object_t xpc_dictionary_create_empty(void){return &fake_dict;}
static void xpc_dictionary_set_uint64(xpc_object_t obj,const char *k,uint64_t v){
    (void)obj; captured[set_calls/2].type = !strcmp(k,"type") ? v : captured[set_calls/2].type;
    if (!strcmp(k,"subtype")) captured[set_calls/2].subtype=v;
    set_calls++;
}
static void xpc_array_set_value(xpc_object_t array,size_t pos,xpc_object_t value){
    (void)array;(void)pos;(void)value;
}
static void xpc_release(xpc_object_t obj){(void)obj;released++;}
#define CHECK(x) do {if(!(x)){fprintf(stderr,"failed line %d: %s\n",__LINE__,#x);return 1;}}while(0)
'''
        cases = r'''
int main(void) {
    struct {int dummy;} state={0};
    struct _posix_spawn_args_desc desc={&state};
    CHECK(rh3_copy_spawn_arch_preferences(NULL)==NULL && count_requested==0);
    CHECK(rh3_copy_spawn_arch_preferences(&desc)==&fake_array);
    CHECK(count_requested==1 && array_calls==1 && set_calls==4 && released==2);
    CHECK(captured[0].type==12 && captured[0].subtype==2);
    CHECK(captured[1].type==13 && captured[1].subtype==3);
    getter_count=5; CHECK(rh3_copy_spawn_arch_preferences(&desc)==NULL);
    getter_count=2; getter_error=22;
    CHECK(rh3_copy_spawn_arch_preferences(&desc)==NULL);
    getter_error=0;requested_types[0]=0;requested_types[1]=0;
    CHECK(rh3_copy_spawn_arch_preferences(&desc)==NULL);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "arch.c"
            exe = Path(d) / "arch.exe"
            src.write_text(prelude.replace("#include <stdbool.h>",
                                           "#include <stdbool.h>\n#include <string.h>") + fn + cases,
                           encoding="utf-8")
            build = subprocess.run([cc, "-std=c11", str(src), "-o", str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=8)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_real_native_policy_rejects_only_failed_active_root_trust(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("No host C compiler")
        src = r'''
#include "roothide_trust_policy.h"
#include <stdio.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); return 1; } } while(0)
int main(void) {
    const char *root="/private/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF";
    const char *active="/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/usr/bin/login";
    const char *other="/var/containers/Bundle/Application/.jbroot-0123456789ABCDE0/usr/bin/login";
    CHECK(rh3_trust_is_active_root_child(active,root));
    CHECK(rh3_trust_is_active_root_child("/private/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/usr/sbin/sshd",root));
    CHECK(!rh3_trust_is_active_root_child(other,root));
    CHECK(!rh3_trust_is_active_root_child("/usr/bin/true",root));
    CHECK(!rh3_trust_is_active_root_child("/",root));
    CHECK(!rh3_trust_is_active_root_child("",root));
    CHECK(!rh3_trust_is_active_root_child(root,root));
    CHECK(!rh3_trust_is_active_root_child("/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF2/bin/login",root));
    CHECK(!rh3_trust_is_active_root_child(NULL,root));
    CHECK(!rh3_trust_is_active_root_child(active,NULL));
    CHECK(rh3_trust_spawn_status(0,true,true)==0);
    CHECK(rh3_trust_spawn_status(-1,true,true)==EACCES);
    CHECK(rh3_trust_spawn_status(-2,true,true)==EACCES);
    CHECK(rh3_trust_spawn_status(23,true,true)==EACCES);
    CHECK(rh3_trust_spawn_status(-1,false,true)==0);
    CHECK(rh3_trust_spawn_status(-1,true,false)==0); // shebang/non-MachO
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            src_file = Path(d) / "test.c"
            binary = Path(d) / "test.exe"
            src_file.write_text(src, encoding="utf-8")
            build = subprocess.run([cc, "-std=c11", "-I", str(HEADER.parent), str(src_file),
                                    "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=8)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_both_spawn_hooks_and_exec_fallback_propagate_trust_errors(self):
        src = MAIN.read_text(encoding="utf-8")
        self.assertIn("#include \"common/roothide_trust_policy.h\"", src)
        self.assertIn("posix_spawnattr_getarchpref_np", src)
        self.assertIn("jbclient_trust_executable_recurse(path, preferredArchs)", src)
        self.assertIn("rh3_trust_spawn_status(trustResult, activeRootChild, isMachO)", src)
        for start, end in [("int __posix_spawn_hook(", "int __posix_spawn_hook_with_filter("),
                           ("int __posix_spawn_hook_with_filter(", "int __execve_hook("),
                           ("int __execve_hook(", "xpc_object_t copy_entitlements_xpc(")]:
            method = src.split(start, 1)[1].split(end, 1)[0]
            self.assertIn("rh3_trust_before_spawn(path,", method)
            self.assertNotIn("jbclient_trust_executable_recurse(path, NULL);", method)


if __name__ == "__main__":
    unittest.main()
