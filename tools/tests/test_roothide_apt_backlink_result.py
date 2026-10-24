"""Exercise production APT backlink error reporting without touching a device."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "BaseBin/libjailbreak/src/roothider/common.m"
HEADER = ROOT / "BaseBin/libjailbreak/src/roothider/common.h"
WALKER = ROOT / "BaseBin/libjailbreak/src/roothider/signatures.m"
SERVER = ROOT / "BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c"


def extract_function(source, marker):
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0
    for position in range(brace, len(source)):
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
            if depth == 0:
                return source[start:position + 1]
    raise AssertionError("unterminated production function")


class AptBacklinkResultTests(unittest.TestCase):
    def test_native_server_never_attaches_after_trust_upload_failure(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("C compiler unavailable")
        source = SERVER.read_text()
        start = source.index("r = trust_signatures(pid, fd, sigInfos, sigInfoCount);")
        end = source.index("// Free allocated signatures", start)
        tail = source[start:end]
        header = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#define SIGNATURE_SOURCE_ALLOCATION 3
#define F_ADDSIGS 71
struct signature { void *fs_blob_start; };
struct siginfo { int source; struct signature signature; };
static int simulatedTrustStatus, attached;
static int trust_signatures(int p, int f, struct siginfo *s, unsigned n) {
  (void)p; (void)f; (void)s; (void)n; return simulatedTrustStatus;
}
static void *siginfo_resolve_superblob(struct siginfo *s, int p, int f) {
  (void)s; (void)p; (void)f; return NULL;
}
static int fake_fcntl(int f, int command, void *sig) {
  (void)f;(void)command;(void)sig;attached++;return 0;
}
#define fcntl fake_fcntl
static int run_production_trust_attach(int trustStatus) {
  int r = 0, pid = 1, fd = 4, attach = 1;
  unsigned sigInfoCount = 1;
  struct siginfo signedItem = { .source=SIGNATURE_SOURCE_ALLOCATION };
  struct siginfo *sigInfos = &signedItem;
  simulatedTrustStatus = trustStatus;
  attached = 0;
'''
        footer = r'''
  return r;
}
int main(void) {
  if (run_production_trust_attach(-7) != -7 || attached != 0) return 1;
  if (run_production_trust_attach(0) != 0 || attached != 1) return 2;
  return 0;
}
'''
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "trust_attach.c"
            exe = Path(temp) / "trust_attach.exe"
            path.write_text(header + tail + footer, encoding="utf-8")
            result = subprocess.run([cc, "-std=c11", str(path), "-o", str(exe)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0,
                             run.stderr + f" (native failure #{run.returncode})")

    def test_recursive_walker_rejects_failed_backlink_setup(self):
        self.assertIn("int ensure_jbroot_symlink(const char* filepath);", HEADER.read_text())
        self.assertIn("int backlinkError = ensure_jbroot_symlink(realLoadPath.fileSystemRepresentation);",
                      WALKER.read_text())
        self.assertIn("if (backlinkError != 0)", WALKER.read_text())
        self.assertIn("if (required) *failed = true;", WALKER.read_text().split("if (backlinkError != 0)", 1)[1][:600])

    def test_native_backlink_failure_and_preservation(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("C compiler unavailable")
        production = extract_function(COMMON.read_text(), "int ensure_jbroot_symlink(")
        scaffold = r'''
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifndef PATH_MAX
#define PATH_MAX 512
#endif
#ifndef F_OK
#define F_OK 0
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_ISLNK
#define S_ISLNK(m) (((m) & 0170000) == S_IFLNK)
#endif
#define JBLogDebug(...) ((void)0)
#define JBLogError(...) ((void)0)
#define JBROOT_PATH(x) "/private/root"
static int testMode, unlinkCalls, symlinkCalls;
static char *fake_realpath(const char *src, char *dst) {
  if (testMode == 7 && strcmp(src, JBROOT_PATH("/")))
    strcpy(dst, "/outside/path/http");
  else if (!strcmp(src, JBROOT_PATH("/"))) strcpy(dst, "/private/root");
  else strcpy(dst, "/private/root/usr/libexec/apt/methods/http");
  return dst;
}
static char *fake_dirname_r(const char *path, char *dst) {
  strcpy(dst, path);
  char *slash = strrchr(dst, '/');
  if (!slash) return NULL;
  *slash = 0;
  return dst;
}
static size_t fake_strlcat(char *dst, const char *src, size_t n) {
  size_t a = strlen(dst), b = strlen(src);
  if (a + b < n) memcpy(dst+a, src, b+1);
  return a+b;
}
static int fake_access(const char *p, int mode) { (void)p;(void)mode;return 0; }
static int fake_stat(const char *p, struct stat *st) {
  memset(st,0,sizeof(*st));
  if (strstr(p,".jbroot")) { st->st_dev = 1; st->st_ino = testMode == 1 ? 9 : 19; }
  else { st->st_dev = 1; st->st_ino = 9; }
  return 0;
}
static int fake_lstat(const char *p, struct stat *st) {
  (void)p; memset(st,0,sizeof(*st));
  if (testMode == 6) { errno=EACCES; return -1; }
  if (testMode == 1 || testMode == 2 || testMode == 5) { st->st_mode=S_IFLNK; return 0; }
  if (testMode == 3) { st->st_mode=0040000; return 0; }
  errno=ENOENT; return -1;
}
static int fake_unlink(const char *p) {
  (void)p; unlinkCalls++;
  if (testMode == 5) { errno=EPERM; return -1; }
  return 0;
}
static int fake_symlink(const char *target, const char *path) {
  (void)target;(void)path; symlinkCalls++;
  if (testMode == 4) { errno=EACCES; return -1; }
  return 0;
}
#define realpath fake_realpath
#define dirname_r fake_dirname_r
#define strlcat fake_strlcat
#define access fake_access
#define stat(...) fake_stat(__VA_ARGS__)
#define lstat(...) fake_lstat(__VA_ARGS__)
#define unlink fake_unlink
#define symlink fake_symlink
'''
        checks = r'''
int main(void) {
  const char *path="/private/root/usr/libexec/apt/methods/http";
  testMode=0;
  if (ensure_jbroot_symlink(path) != 0 || symlinkCalls != 1) return 1;
  testMode=1; unlinkCalls=symlinkCalls=0;
  if (ensure_jbroot_symlink(path) != 0 || unlinkCalls || symlinkCalls) return 2;
  testMode=3; unlinkCalls=symlinkCalls=0;
  if (ensure_jbroot_symlink(path) == 0 || unlinkCalls || symlinkCalls) return 3;
  testMode=4; unlinkCalls=symlinkCalls=0;
  if (ensure_jbroot_symlink(path) != EACCES || unlinkCalls || symlinkCalls!=1) return 4;
  testMode=5; unlinkCalls=symlinkCalls=0;
  if (ensure_jbroot_symlink(path) != EPERM || unlinkCalls!=1 || symlinkCalls) return 5;
  testMode=6; unlinkCalls=symlinkCalls=0;
  if (ensure_jbroot_symlink(path) != EACCES || unlinkCalls || symlinkCalls) return 6;
  testMode=7; unlinkCalls=symlinkCalls=0;
  if (ensure_jbroot_symlink(path) != 0 || unlinkCalls || symlinkCalls) return 7;
  return 0;
}
'''
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "backlink.c"
            exe = Path(temp) / "backlink.exe"
            file.write_text(scaffold + production + checks, encoding="utf-8")
            compile_result = subprocess.run([cc, "-std=c11", str(file), "-o", str(exe)],
                                            capture_output=True, text=True, timeout=30)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0,
                             run.stderr + f" (native failure #{run.returncode})")


if __name__ == "__main__":
    unittest.main()
