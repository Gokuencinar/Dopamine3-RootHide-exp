"""Safe-mode migration regressions based on production code and host C checks.

Host GCC cannot model iOS CS_INSTALLER, AppGroup or launchd. These checks
exercise the file-metadata refusal helper and constrain risky source paths;
the actual native iOS target must additionally pass an Xcode build.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "Application/Dopamine/Jailbreak/RH3TweakToggle.h").read_text(encoding="utf-8")
APP = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(encoding="utf-8")
BOOT = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text(encoding="utf-8")
WATCHDOG = (ROOT / "BaseBin/launchdhook/src/jbserver/jbdomain_watchdog.c").read_text(encoding="utf-8")
HOOK = (ROOT / "BaseBin/systemhook/src/main.c").read_text(encoding="utf-8")
SETTINGS = (ROOT / "Application/Dopamine/UI/Settings/DOSettingsController.m").read_text(encoding="utf-8")


class SafeModeMigrationR173(unittest.TestCase):
    def test_real_request_reader_rejects_corruption_and_accepts_only_exact_choices(self):
        compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not compiler:
            self.skipTest("No C compiler")
        verifier = "static inline int rh3_tweak_request_verify" + HEADER.split(
            "static inline int rh3_tweak_request_verify", 1
        )[1].split("// The watchdog can set this latch", 1)[0]
        reader = "static inline int rh3_tweak_request_read" + HEADER.split(
            "static inline int rh3_tweak_request_read", 1
        )[1].split("static inline int rh3_tweak_request_cancel", 1)[0]
        harness = r'''
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#define RH3_TWEAK_REQUEST_NAME ".roothide3-tweak-toggle.pending"
#define RH3_TWEAK_REQUEST_ENABLE "RH3_TWEAK_V1:E\n"
#define RH3_TWEAK_REQUEST_DISABLE "RH3_TWEAK_V1:D\n"
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif
static struct stat metadata;
static const char *payload;
static int stat_error, read_error;
static int fake_open_request_dir(const char *root, const char *secondary, int *out) {
    if (!root || !secondary) return EINVAL;
    *out=8; return 0;
}
static int fake_statat(int dir, const char *name, struct stat *st, int flags) {
    if (dir != 8 || strcmp(name, RH3_TWEAK_REQUEST_NAME) || flags != AT_SYMLINK_NOFOLLOW)
        return -1;
    if (stat_error) { errno=stat_error; return -1; }
    *st=metadata; return 0;
}
static int fake_openat(int dir, const char *name, int flags) {
    (void)flags;
    return dir == 8 && !strcmp(name, RH3_TWEAK_REQUEST_NAME) ? 13 : -1;
}
static ssize_t fake_read(int fd, void *buffer, size_t capacity) {
    if (fd != 13) return -1;
    if (read_error) { errno=read_error; return -1; }
    size_t length=strlen(payload);
    if (length > capacity) length=capacity;
    memcpy(buffer,payload,length); return (ssize_t)length;
}
static int fake_fstat(int fd, struct stat *st) {
    if (fd != 13) return -1;
    *st=metadata; return 0;
}
static int fake_close(int fd) { return fd == 8 || fd == 13 ? 0 : -1; }
#define rh3_tweak_open_request_dir fake_open_request_dir
#define fstatat fake_statat
#define openat fake_openat
#define read fake_read
#define fstat fake_fstat
#define close fake_close
''' + verifier + reader + r'''
#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "request reader check line %d: %s\n", __LINE__, #cond); return 1; } } while(0)
int main(void) {
    bool enabled=false;
    metadata.st_mode=S_IFREG | 0600;
    metadata.st_uid=0;
    metadata.st_nlink=1;
    payload=RH3_TWEAK_REQUEST_ENABLE;
    metadata.st_size=(long)strlen(payload);
    CHECK(rh3_tweak_request_read("root","secondary",&enabled)==0 && enabled);
    enabled=true; payload=RH3_TWEAK_REQUEST_DISABLE;
    metadata.st_size=(long)strlen(payload);
    CHECK(rh3_tweak_request_read("root","secondary",&enabled)==0 && !enabled);
    payload="RH3_TWEAK_V1:X\n"; metadata.st_size=(long)strlen(payload);
    CHECK(rh3_tweak_request_read("root","secondary",&enabled)==EINVAL);
    payload="RH3_TWEAK_V1:E\nextra"; metadata.st_size=(long)strlen(payload);
    CHECK(rh3_tweak_request_read("root","secondary",&enabled)==EPERM);
    payload=RH3_TWEAK_REQUEST_ENABLE; metadata.st_size=2;
    CHECK(rh3_tweak_request_read("root","secondary",&enabled)==EPERM);
    metadata.st_size=(long)strlen(payload); metadata.st_uid=501;
    CHECK(rh3_tweak_request_read("root","secondary",&enabled)==EPERM);
    metadata.st_uid=0; metadata.st_mode=S_IFREG | 0644;
    CHECK(rh3_tweak_request_read("root","secondary",&enabled)==EPERM);
    metadata.st_mode=S_IFREG | 0600;
    stat_error=ENOENT;
    CHECK(rh3_tweak_request_read("root","secondary",&enabled)==ENOENT);
    stat_error=EACCES;
    CHECK(rh3_tweak_request_read("root","secondary",&enabled)==EACCES);
    stat_error=0; read_error=EIO;
    CHECK(rh3_tweak_request_read("root","secondary",&enabled)!=0);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as temp:
            source, binary = Path(temp) / "reader.c", Path(temp) / "reader.exe"
            source.write_text(harness, encoding="utf-8")
            compile_result = subprocess.run(
                [compiler, "-std=c11", str(source), "-o", str(binary)],
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            result = subprocess.run([str(binary)], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_actual_production_file_verifier_handles_negative_cases(self):
        compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not compiler:
            self.skipTest("No C compiler")
        segment = "static inline int rh3_tweak_request_verify" + HEADER.split(
            "static inline int rh3_tweak_request_verify", 1
        )[1].split("// The watchdog can set this latch", 1)[0]
        program = r'''
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#define RH3_TWEAK_REQUEST_NAME ".roothide3-tweak-toggle.pending"
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
static struct stat fake;
static int result_error;
static int fake_stat(int dir,const char *path,struct stat *out,int flags) {
    if (dir != 8 || flags != AT_SYMLINK_NOFOLLOW) return -1;
    if (result_error) { errno = result_error; return -1; }
    *out = fake; return 0;
}
#define fstatat fake_stat
''' + segment + r'''
#define CHECK(x) do { if (!(x)) return __LINE__; } while(0)
int main(void) {
    bool exists = false;
    fake.st_mode = S_IFREG | 0600;
    fake.st_uid = 0;
    fake.st_nlink = 1;
    fake.st_size = 14;
    CHECK(rh3_tweak_request_verify(8,&exists) == 0 && exists);
    fake.st_uid = 501; CHECK(rh3_tweak_request_verify(8,&exists) == EPERM);
    fake.st_uid = 0; fake.st_nlink = 2;
    CHECK(rh3_tweak_request_verify(8,&exists) == EPERM);
    fake.st_nlink = 1; fake.st_mode = S_IFLNK | 0600;
    CHECK(rh3_tweak_request_verify(8,&exists) == EPERM);
    fake.st_mode = S_IFREG | 0644;
    CHECK(rh3_tweak_request_verify(8,&exists) == EPERM);
    fake.st_mode = S_IFREG | 0600; fake.st_size = 65;
    CHECK(rh3_tweak_request_verify(8,&exists) == EPERM);
    result_error = ENOENT; exists = true;
    CHECK(rh3_tweak_request_verify(8,&exists) == 0 && !exists);
    result_error = EACCES;
    CHECK(rh3_tweak_request_verify(8,&exists) == EACCES);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as temp:
            src, exe = Path(temp) / "verify.c", Path(temp) / "verify.exe"
            src.write_text(program, encoding="utf-8")
            compile_result = subprocess.run(
                [compiler, str(src), "-o", str(exe)], capture_output=True,
                text=True, timeout=20,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_installer_phase_only_applies_explicit_pending_request(self):
        body = BOOT.split("static int RH3ApplyStagedTweakChoice(", 1)[1].split(
            "@implementation DOJailbreaker", 1
        )[0]
        self.assertIn("rh3_tweak_request_read", body)
        self.assertIn("if (status == ENOENT) return 0", body)
        self.assertIn("CS_INSTALLER", body)
        self.assertIn("CS_PLATFORM_BINARY", body)
        self.assertLess(body.index("CS_INSTALLER"), body.index("unlinkat(basebin"))
        self.assertIn('openat(basebin, ".safe_mode"', body)
        self.assertIn("rh3_tweak_watchdog_clear", body)
        self.assertIn("rh3_tweak_request_cancel", body)
        self.assertNotIn("proc_csflags_set", body)
        self.assertIn("invalidRequest = status == EINVAL || status == EPERM", body)
        self.assertIn("rh3_tweak_open_request_dir", body)
        self.assertIn("enable = false", body)
        self.assertIn("if (invalidRequest)", body)
        self.assertLess(body.index("enable = false"), body.index("unlinkat(basebin"))
        self.assertIn("request retained for explicit replacement", body)
        staging = HEADER.split("static inline int rh3_tweak_request_stage", 1)[1]
        self.assertIn("renameat(directory, temp, directory, RH3_TWEAK_REQUEST_NAME)", staging)
        self.assertNotIn("rh3_tweak_request_verify", staging)
        cancel = HEADER.split("static inline int rh3_tweak_request_cancel", 1)[1].split(
            "static inline int rh3_tweak_request_stage", 1
        )[0]
        self.assertIn("unlinkat(directory, RH3_TWEAK_REQUEST_NAME, 0)", cancel)
        self.assertNotIn("rh3_tweak_request_verify", cancel)
        flow = BOOT.split("*errOut = [[DOEnvironmentManager sharedManager] prepareBootstrap];", 1)[1]
        self.assertLess(flow.index("RH3ApplyStagedTweakChoice"), flow.index("injectLaunchdHook"))
        self.assertIn("&& !removeJailbreakEnabled", flow.split("RH3ApplyStagedTweakChoice", 1)[0])

    def test_postboot_app_stages_writable_request_without_claiming_success(self):
        method = APP.split("- (int)setTweakInjectionEnabled:(BOOL)enabled", 1)[1].split(
            "- (BOOL)isIDownloadEnabled", 1
        )[0]
        self.assertIn("rh3_tweak_request_stage", method)
        self.assertIn("rh3_tweak_watchdog_latched", method)
        self.assertIn("if (status == 0 && stagedPending) status = EINPROGRESS", method)
        self.assertIn("if (status == 0 && unchanged) status = EALREADY", method)
        self.assertNotIn("rh3_tweak_watchdog_clear", method)
        self.assertNotIn("unlink(safeModePath", method)
        self.assertNotIn("open(safeModePath", method)
        self.assertIn("cancelRootHideTweakInjectionRequest", method)
        cancel = method.split("- (int)cancelRootHideTweakInjectionRequest", 1)[1]
        self.assertIn("rh3_tweak_request_cancel", cancel)
        self.assertNotIn("rh3_tweak_watchdog_clear", cancel)
        getter = APP.split("- (BOOL)isTweakInjectionEnabled", 1)[1].split(
            "- (int)setTweakInjectionEnabled", 1
        )[0]
        self.assertIn("rh3_tweak_watchdog_latched", getter)
        self.assertIn("markerPresent = YES", getter)
        self.assertIn("if (result)", getter)
        self.assertIn("status == EINPROGRESS", SETTINGS)
        self.assertIn("status == EALREADY", SETTINGS)
        self.assertIn("cancelRootHideTweakRequestPressed", SETTINGS)
        self.assertIn("cancelRootHideTweakInjectionRequest", SETTINGS)
        self.assertIn("no se realizará un reinicio de espacio de usuario ahora", SETTINGS)

    def test_watchdog_latch_is_fail_closed_and_not_automatically_cleared(self):
        self.assertIn('openat(parent, ".roothide3-watchdog-safe-mode"', WATCHDOG)
        self.assertIn("O_NOFOLLOW | O_CLOEXEC, 0600", WATCHDOG)
        self.assertIn("fsync(markerFD)", WATCHDOG)
        self.assertIn("fsync(parent)", WATCHDOG)
        entry = HOOK.split("bool should_enable_tweaks(void)", 1)[1].split(
            "int __posix_spawn_hook(", 1
        )[0]
        self.assertIn('JBROOT_PATH("/var/.roothide3-watchdog-safe-mode")', entry)
        self.assertIn("if (errno != ENOENT) return false", entry)
        self.assertLess(entry.index(".roothide3-watchdog-safe-mode"), entry.index("basebin/.safe_mode"))
        self.assertNotIn("unlink(", entry)


if __name__ == "__main__":
    unittest.main()
