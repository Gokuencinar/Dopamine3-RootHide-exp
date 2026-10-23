"""Execute the actual jbctl mount-policy functions with mocked system calls.

This asserts RootHide never mounts/unmounts stock preboot or global /usr/lib
via jbctl, while the ordinary Dopamine path retains its original behavior.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "BaseBin/jbctl/src/internal.m"


class StockMountPolicyTests(unittest.TestCase):
    def test_safe_mount_dispatch_and_no_regression_for_stock(self):
        compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not compiler:
            self.skipTest("Native C compiler unavailable")
        code = SOURCE.read_text(encoding="utf-8")
        detector = code.split("static bool rh3_jbctl_hidden_root_from_checked_in_state(void)", 1)[1].split(
            "int protection_set_active(bool active)", 1)[0]
        protection = code.split("int protection_set_active(bool active)", 1)[1].split(
            "bool fakelib_is_mounted(void)", 1)[0]
        fakelib = code.split("int fakelib_set_mounted(bool mounted)", 1)[1].split(
            "int jbctl_handle_internal(", 1)[0]
        self.assertIn("rh3_jbctl_hidden_root_from_checked_in_state()) return 0;", protection)
        self.assertIn("rh3_jbctl_hidden_root_from_checked_in_state()) return ENOTSUP;", fakelib)
        self.assertIn("jbinfo(rootPath)", detector)
        self.assertIn("rootLength != n + 16", detector)
        self.assertIn('if (statfs(path, &sb) != 0) return false;', code)

        prelude = r'''
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
static size_t test_strnlen(const char *s, size_t max) {
    size_t n = 0;
    while (n < max && s[n] != 0) n++;
    return n;
}
#define strnlen test_strnlen
#ifndef ENOTSUP
#define ENOTSUP 95
#endif
static bool rootHide, mounted;
static const char *fake_rootPath="/private/preboot/test";
#define jbinfo(field) fake_##field
static int protectedCalls, unprotectedCalls, mounts, unmounts;
#define MNT_RDONLY 1
#define JBROOT_PATH(path) path
static bool roothide_is_active(void) { return rootHide; }
static const char *prebootUUIDPath(const char *suffix) { return suffix; }
static int ensure_protected(const char *path) {
    if (!strcmp(path,"/System") || !strcmp(path,"/usr")) protectedCalls++;
    return 0;
}
static int ensure_unprotected(const char *path) {
    if (!strcmp(path,"/System") || !strcmp(path,"/usr")) unprotectedCalls++;
    return 0;
}
static bool fakelib_is_mounted(void) { return mounted; }
static int mount_unsandboxed(const char *fs,const char *path,int flags,void *data) {
    (void)fs;(void)flags;(void)data;
    if (!strcmp(path,"/usr/lib")) mounts++;
    return 0;
}
static int unmount_unsandboxed(const char *path,int flags) {
    (void)flags;
    if (!strcmp(path,"/usr/lib")) unmounts++;
    return 0;
}
#define MNT_FORCE 2
#define CHECK(x) do { if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);return 1;} }while(0)
'''
        main = r'''
int main(void) {
    rootHide=true;
    CHECK(protection_set_active(true)==0);
    CHECK(protection_set_active(false)==0);
    CHECK(fakelib_set_mounted(true)==ENOTSUP);
    CHECK(fakelib_set_mounted(false)==ENOTSUP);
    CHECK(protectedCalls==0 && unprotectedCalls==0 && mounts==0 && unmounts==0);
    // jbctl receives rootPath on check-in but jbrand may still be zero.
    // The guard must work even when the brand-dependent predicate is false.
    rootHide=false;
    fake_rootPath="/private/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF";
    CHECK(protection_set_active(true)==0);
    CHECK(protection_set_active(false)==0);
    CHECK(fakelib_set_mounted(true)==ENOTSUP);
    CHECK(protectedCalls==0 && unprotectedCalls==0 && mounts==0 && unmounts==0);
    fake_rootPath="/var/containers/Bundle/Application/.jbroot-0123456789abcdef";
    CHECK(protection_set_active(true)==0 && protectedCalls==0);
    fake_rootPath="/private/var/containers/Bundle/Application/.jbroot-0123456789ABCDEG";
    CHECK(protection_set_active(true)==0 && protectedCalls==2);
    protectedCalls=0;
    fake_rootPath="/private/preboot/test";
    rootHide=false;
    CHECK(protection_set_active(true)==0 && protectedCalls==2);
    CHECK(protection_set_active(false)==0 && unprotectedCalls==2);
    mounted=false;
    CHECK(fakelib_set_mounted(true)==0 && mounts==1);
    mounted=true;
    CHECK(fakelib_set_mounted(false)==0 && unmounts==1);
    CHECK(fakelib_set_mounted(true)==0 && mounts==1);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "mount_policy.c"
            exe = Path(tmp) / "mount_policy.exe"
            file.write_text(prelude + "static bool rh3_jbctl_hidden_root_from_checked_in_state(void)" +
                            detector + "int protection_set_active(bool active)" + protection +
                            "int fakelib_set_mounted(bool mounted)" + fakelib + main,
                            encoding="utf-8")
            built = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                    str(file), "-o", str(exe)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            executed = subprocess.run([str(exe)], capture_output=True, text=True, timeout=15)
            self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()
