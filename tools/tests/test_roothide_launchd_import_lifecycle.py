"""Execute the actual launchd plist import function with a bounded host stub.

This covers malformed launchd package input and ownership; it cannot prove
that Apple's launchd actually reimports com.openssh.sshd after a reboot.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "BaseBin/launchdhook/src/daemon_hook.m"


class LaunchDaemonImport(unittest.TestCase):
    def test_job_type_label_bounded_open_and_xpc_ownership(self):
        compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not compiler:
            self.skipTest("Host C compiler not found")
        code = SOURCE.read_text(encoding="utf-8")
        function = code.split("void xpc_dictionary_add_launch_daemon_plist_at_path(", 1)[1]
        function = "void xpc_dictionary_add_launch_daemon_plist_at_path(" + function.split(
            "xpc_object_t (*xpc_dictionary_get_value_orig)", 1
        )[0]
        stub = r'''
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#ifndef O_CLOEXEC
#define O_CLOEXEC 0x100000
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0x1000
#endif
#ifndef S_ISREG
#define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
#endif
#define PROT_READ 1
#define MAP_PRIVATE 2
#define MAP_FILE 0
#define MAP_FAILED ((void*)-1)
#define XPC_TYPE_DICTIONARY ((void*)0x15)
typedef void* xpc_object_t;
static int config, opened, mapped, parsed, released, inserted, closed, unmapped;
static const char data[] = "plist";
static int fake_open(const char *path, int flags) {
    if (!(flags & O_NONBLOCK) || !(flags & O_CLOEXEC)) return -1;
    opened++;
    return config == 6 ? -1 : 80;
}
static int fake_fstat(int fd, struct stat *st) {
    if (fd != 80 || config == 5) return -1;
    memset(st, 0, sizeof(*st));
    st->st_mode = (config == 3 ? S_IFIFO : S_IFREG) | 0644;
    st->st_size = config == 4 ? 5 * 1024 * 1024 : 5;
    return 0;
}
static void *fake_mmap(void *addr, size_t length, int prot, int flags, int fd, long offset) {
    mapped++;
    return (void*)data;
}
static int fake_munmap(void *addr, size_t size) { unmapped++; return 0; }
static int fake_close(int fd) { closed++; return 0; }
static xpc_object_t xpc_create_from_plist(const void *bytes, size_t size) {
    parsed++;
    return config == 7 ? NULL : (void*)0x19;
}
static void *xpc_get_type(xpc_object_t object) {
    return config == 1 ? (void*)0x17 : XPC_TYPE_DICTIONARY;
}
static const char *xpc_dictionary_get_string(xpc_object_t dict, const char *key) {
    return (config == 2 || strcmp(key, "Label")) ? NULL : "com.openssh.sshd";
}
static void xpc_dictionary_set_value(xpc_object_t dict, const char *path, xpc_object_t value) {
    if (!strcmp(path, "test.plist")) inserted++;
}
static void xpc_release(xpc_object_t value) { released++; }
#define open fake_open
#define fstat fake_fstat
#define mmap fake_mmap
#define munmap fake_munmap
#define close fake_close
'''
        cases = r'''
static int run_case(int scenario, int eInsert, int eParse, int eRelease) {
    config=scenario; opened=mapped=parsed=released=inserted=closed=unmapped=0;
    xpc_dictionary_add_launch_daemon_plist_at_path((void*)0x40,"test.plist");
    if (inserted != eInsert || parsed != eParse || released != eRelease) return scenario+1;
    if (unmapped != eParse || closed != (scenario == 6 ? 0 : 1)) return scenario+11;
    return 0;
}
int main(void) {
    if (run_case(0,1,1,1)) return 1; // valid package job
    if (run_case(1,0,1,1)) return 2; // wrong XPC type
    if (run_case(2,0,1,1)) return 3; // missing required Label
    if (run_case(3,0,0,0)) return 4; // pipe: reject before mapping
    if (run_case(4,0,0,0)) return 5; // oversized: reject before mapping
    if (run_case(5,0,0,0)) return 6; // failed fstat: close descriptor
    if (run_case(6,0,0,0)) return 7; // inaccessible package entry
    config=7; opened=mapped=parsed=released=inserted=closed=unmapped=0;
    xpc_dictionary_add_launch_daemon_plist_at_path((void*)0x40,"test.plist");
    if (inserted || released || parsed != 1 || unmapped != 1 || closed != 1) return 8;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "import.c"
            binary = Path(directory) / "import.exe"
            path.write_text(stub + function + cases, encoding="utf-8")
            compiled = subprocess.run([compiler, str(path), "-o", str(binary)],
                                      capture_output=True, text=True, timeout=20)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            tested = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(tested.returncode, 0, tested.stderr)


if __name__ == "__main__":
    unittest.main()
