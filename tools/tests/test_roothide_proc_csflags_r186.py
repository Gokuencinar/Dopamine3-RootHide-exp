"""Production proc_patch_csflags() with fault-injected kernel I/O (host only)."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "BaseBin/libjailbreak/src/roothider/common.m"

HARNESS = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef int pid_t;
typedef struct { uint32_t csflags; uint32_t padding; uint64_t proc_ro; } proc;
typedef struct { uint32_t csflags; } proc_ro;
enum { KOFF_proc_csflags=0, KOFF_proc_proc_ro=8, KOFF_proc_ro_csflags=0 };
#define koffsetof(type, field) KOFF_##type##_##field
#define CS_GET_TASK_ALLOW 0x4u
#define CHECK(expr) do { if(!(expr)) { fprintf(stderr,"line %d: %s\n",__LINE__,#expr); return 1; } } while(0)
struct { struct { struct { bool exists; } proc_ro; } kernelStruct; } gSystemInfo;
static unsigned char kernel[512];
static int fail_read, fail_write, corrupt_write, read_count, write_count, missing_proc;
static uint64_t proc_find(pid_t pid) { return !missing_proc && pid==42 ? 32 : 0; }
static int valid(uint64_t addr,size_t sz) { return addr && addr<sizeof(kernel) && sz<=sizeof(kernel)-addr; }
static int kreadbuf(uint64_t addr,void *dst,size_t size) {
    read_count++;
    if (!valid(addr,size) || (fail_read && read_count==fail_read)) return -1;
    memcpy(dst,kernel+addr,size); return 0;
}
static uint64_t kread_ptr(uint64_t addr) {
    uint64_t result=0; return kreadbuf(addr,&result,sizeof(result))==0 ? result : 0;
}
static int kwrite32(uint64_t addr,uint32_t value) {
    write_count++;
    if (!valid(addr,sizeof(value)) || fail_write) return -1;
    if (!corrupt_write) memcpy(kernel+addr,&value,sizeof(value));
    return 0;
}
/* PRODUCTION_PATCH */
static void setup(bool ro) {
    memset(kernel,0,sizeof(kernel));
    gSystemInfo.kernelStruct.proc_ro.exists=ro;
    uint64_t roaddr=160;
    memcpy(kernel+32+offsetof(proc,proc_ro),&roaddr,sizeof(roaddr));
    fail_read=fail_write=corrupt_write=read_count=write_count=missing_proc=0;
}
static uint32_t flags_at(bool ro) {
    uint32_t result=0;
    memcpy(&result,kernel+(ro ? 160+offsetof(proc_ro,csflags):32+offsetof(proc,csflags)),4);
    return result;
}
int main(void) {
    setup(false); CHECK(proc_patch_csflags(42)==0 && (flags_at(false)&CS_GET_TASK_ALLOW));
    setup(true); CHECK(proc_patch_csflags(42)==0 && (flags_at(true)&CS_GET_TASK_ALLOW));
    setup(false); missing_proc=1; CHECK(proc_patch_csflags(42)!=0 && write_count==0);
    setup(false); fail_read=1; CHECK(proc_patch_csflags(42)!=0 && write_count==0);
    setup(true); fail_read=1; CHECK(proc_patch_csflags(42)!=0 && write_count==0);
    setup(false); fail_write=1; CHECK(proc_patch_csflags(42)!=0);
    setup(false); corrupt_write=1; CHECK(proc_patch_csflags(42)!=0);
    setup(false); uint32_t preexisting=CS_GET_TASK_ALLOW|0x200u;
    memcpy(kernel+32,&preexisting,sizeof(preexisting));
    CHECK(proc_patch_csflags(42)==0 && write_count==0 && flags_at(false)==preexisting);
    return 0;
}
'''


class ProcCSFlagsR186(unittest.TestCase):
    def test_real_function_read_write_and_readback(self):
        cc = shutil.which("gcc") or shutil.which("clang")
        if not cc:
            self.skipTest("No native C compiler")
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("int proc_patch_csflags(pid_t pid)")
        end = source.index("#define P_LTRACED", start)
        code = HARNESS.replace("/* PRODUCTION_PATCH */", source[start:end])
        with tempfile.TemporaryDirectory(prefix="rh3-csflags-") as temp:
            path = Path(temp) / "csflags.c"
            exe = Path(temp) / "csflags.exe"
            path.write_text(code, encoding="utf-8")
            built = subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                    str(path), "-o", str(exe)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
