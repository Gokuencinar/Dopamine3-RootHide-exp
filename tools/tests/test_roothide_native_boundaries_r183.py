"""Compile production C helpers with fake OS dependencies (not an iPhone test)."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PID1 = ROOT / "BaseBin/launchdhook/src/spawn_hook.c"
MACH = ROOT / "BaseBin/libjailbreak/src/jbclient_mach.c"
SIGNATURES = ROOT / "BaseBin/libjailbreak/src/signatures.c"
LIB_HEADER = ROOT / "BaseBin/libjailbreak/src/RH3MachOLibraryType.h"


def compiled(source: str, name: str):
    cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    if not cc:
        raise unittest.SkipTest("No C compiler")
    with tempfile.TemporaryDirectory() as tmp:
        file = Path(tmp) / f"{name}.c"
        exe = Path(tmp) / f"{name}.exe"
        file.write_text(source, encoding="utf-8")
        built = subprocess.run([cc, "-std=c11", "-Wall", "-Wextra",
                                str(file), "-o", str(exe)],
                               capture_output=True, text=True, timeout=25)
        if built.returncode:
            raise AssertionError(built.stderr)
        ran = subprocess.run([str(exe)], capture_output=True, text=True, timeout=5)
        if ran.returncode:
            raise AssertionError(f"{name} returned {ran.returncode}: {ran.stderr}")


class NativeBoundaries(unittest.TestCase):
    def test_real_origin_verifier_accepts_var_alias_but_not_spoofed_root(self):
        src = PID1.read_text(encoding="utf-8")
        origin = src.split("bool roothide_launchdhook_origin_verified(void)", 1)[1].split(
            "void ensure_fakelib_mounted(void)", 1)[0]
        alias = src.rsplit("static const char *rh3_pid1_var_alias_n(", 1)[1].split(
            "static bool rh3_pid1_private_dyld_target", 1)[0]
        program = r'''
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#define PATH_MAX 4096
typedef struct { const char *dli_fname; } Dl_info;
static const char *root, *image;
static const char *get_jbroot(void) { return root; }
static bool systemhook_is_roothide_root_path(const char *r) {
 const char *base = strstr(r ? r : "", "/.jbroot-");
 if (!base || base[9] == 0 || strlen(base+9)!=16) return false;
 for (const char *p=base+9;*p;p++)
    if (!((*p>='0'&&*p<='9')||(*p>='A'&&*p<='F'))) return false;
 return true;
}
static int dladdr(const void *p, Dl_info *d) {
 (void)p; if (!image) return 0; d->dli_fname=image; return 1;
}
static const char *rh3_pid1_var_alias_n(const char *path, size_t *length);
bool roothide_launchdhook_origin_verified(void)
''' + origin + r'''
static const char *rh3_pid1_var_alias_n(''' + alias + r'''
#define ASSERT(v) do { if(!(v)) return __LINE__; }while(0)
int main(void) {
 const char *a="/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF";
 const char *b="/private/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF";
 root=a; image="/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/basebin/launchdhook.dylib";
 ASSERT(roothide_launchdhook_origin_verified());
 root=b; ASSERT(roothide_launchdhook_origin_verified());
 root=a; image="/private/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/basebin/launchdhook.dylib";
 ASSERT(roothide_launchdhook_origin_verified());
 root=b; ASSERT(roothide_launchdhook_origin_verified());
 root="/private/var/containers/Bundle/Application/.jbroot-FFFFFFFFFFFFFFFF";
 ASSERT(!roothide_launchdhook_origin_verified());
 root=a; image="/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/basebin/launchdhook.dylib.evil";
 ASSERT(!roothide_launchdhook_origin_verified());
 image="/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/basebin/systemhook.dylib";
 ASSERT(!roothide_launchdhook_origin_verified());
 image=NULL; ASSERT(!roothide_launchdhook_origin_verified());
 root="/private/var/not-root"; ASSERT(!roothide_launchdhook_origin_verified());
 return 0;
}
'''
        compiled(program, "origin")

    def test_registered_ports_zero_invalid_and_valid_cases(self):
        src = MACH.read_text(encoding="utf-8")
        body = src.split("mach_port_t jbclient_mach_get_launchd_port(void)", 1)[1].split(
            "kern_return_t jbclient_mach_send_msg(", 1)[0]
        program = r'''
#include <stddef.h>
#include <stdint.h>
typedef unsigned int mach_port_t;
typedef mach_port_t *mach_port_array_t;
typedef unsigned int mach_msg_type_number_t;
typedef unsigned int kern_return_t;
typedef uintptr_t vm_address_t;
#define MACH_PORT_NULL 0
#define MACH_PORT_VALID(x) ((x)!=0 && (x)!=~(mach_port_t)0)
#define KERN_SUCCESS 0
static mach_port_t supplied_boot, ports[3] = {41,0,43};
static unsigned count, return_null, lookup_fail, dealloc_count, vm_count;
static mach_port_t mach_task_self(void) { return 99; }
static kern_return_t task_get_bootstrap_port(mach_port_t task,mach_port_t *out) {
 (void)task; *out=supplied_boot; return 0;
}
static kern_return_t mach_ports_lookup(mach_port_t task,mach_port_t **out,mach_msg_type_number_t *n) {
 (void)task; if(lookup_fail) return 1; *out=return_null?NULL:ports;*n=count; return 0;
}
static kern_return_t mach_port_deallocate(mach_port_t task,mach_port_t p) {
 (void)task;(void)p;dealloc_count++;return 0;
}
static kern_return_t vm_deallocate(mach_port_t task,vm_address_t addr,size_t n) {
 (void)task;(void)addr;(void)n;vm_count++;return 0;
}
mach_port_t jbclient_mach_get_launchd_port(void)
''' + body + r'''
#define ASSERT(v) do { if(!(v)) return __LINE__; }while(0)
int main(void) {
 supplied_boot=77; ASSERT(jbclient_mach_get_launchd_port()==77);
 supplied_boot=0; count=0; ASSERT(jbclient_mach_get_launchd_port()==0);
 count=1;return_null=1;ASSERT(jbclient_mach_get_launchd_port()==0);
 return_null=0;ports[0]=0;dealloc_count=0;
 ASSERT(jbclient_mach_get_launchd_port()==0 && dealloc_count==0);
 ports[0]=41;dealloc_count=0;count=3;
 ASSERT(jbclient_mach_get_launchd_port()==41 && dealloc_count==1);
 ASSERT(vm_count==2);
 lookup_fail=1;ASSERT(jbclient_mach_get_launchd_port()==0);
 return 0;
}
'''
        compiled(program, "mach_registered_ports")

    def test_real_library_filetype_helper_rejects_executables(self):
        header = LIB_HEADER.read_text(encoding="utf-8")
        src = SIGNATURES.read_text(encoding="utf-8")
        self.assertIn("rh3_macho_is_library_type(header->filetype)", src)
        program = r'''
#include <stdbool.h>
#include <stdint.h>
#define MH_EXECUTE 2
#define MH_DYLIB 6
#define MH_BUNDLE 8
''' + header + r'''
int main(void) {
 if(rh3_macho_is_library_type(MH_EXECUTE)) return 1;
 if(!rh3_macho_is_library_type(MH_DYLIB)) return 2;
 if(!rh3_macho_is_library_type(MH_BUNDLE)) return 3;
 if(rh3_macho_is_library_type(0)) return 4;
 return 0;
}
'''
        compiled(program, "library_type")


if __name__ == "__main__":
    unittest.main()
