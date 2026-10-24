"""Exercise the only automatic lsd uicache child wait and its fail-closed gate."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "BaseBin/roothidehooks/lsd.x").read_text()


class LsdUICacheTests(unittest.TestCase):
    def test_root_hide3_explicit_registrations_do_not_spawn_second_uicache(self):
        method = SOURCE.split("int new_LSServer_RebuildApplicationDatabases()", 1)[1].split(
            "void lsdInit(", 1)[0]
        self.assertIn('jbroot("/.installed_roothide3")', method)
        self.assertLess(method.index('access(rh3Marker, F_OK) == 0'),
                        method.index("posix_spawn(&pid, uicachePath"))
        self.assertIn("if (!timedOut) __sync_lock_release", method)
        self.assertNotIn("wait_for_exit(pid)", method)

    def test_native_wait_reaps_exited_child_and_bounds_stuck_child(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("Host C compiler unavailable")
        code = SOURCE.split("static int rh3_wait_auto_uicache(", 1)[1].split(
            "int new_LSServer_RebuildApplicationDatabases()", 1)[0]
        function = "static int rh3_wait_auto_uicache(" + code
        prefix = r"""
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
// MinGW host CI has no Darwin sys/wait.h. Model only the POSIX wait-status
// bits used by this production helper (zero is a clean child exit).
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT 110
#endif
typedef int pid_t;
#define WNOHANG 1
#define WIFEXITED(status) (((status) & 127) == 0)
#define WIFSIGNALED(status) (((status) & 127) != 0)
#define WEXITSTATUS(status) (((status) >> 8) & 255)
#define WTERMSIG(status) ((status) & 127)
static int mode, calls, kills, slept;
static pid_t fake_waitpid(pid_t child, int *status, int flags) {
    if (flags!=WNOHANG || child!=223) return -1;
    calls++;
    if (mode==0 && calls==3) { *status=0; return child; }
    if (mode==0) return 0;
    if (mode==1) return 0;
    errno=ECHILD;
    return -1;
}
static int fake_kill(pid_t pid, int sig) {
    if(pid!=223 || sig!=SIGKILL) return -1;
    kills++; return 0;
}
static int fake_sleep(unsigned long microseconds) {
    (void)microseconds; slept++; return 0;
}
#define waitpid fake_waitpid
#define kill fake_kill
#define usleep fake_sleep
"""
        suffix = r"""
int main(void) {
    if(rh3_wait_auto_uicache(1)!=ECHILD || calls!=0) return 1;
    mode=0; calls=0; kills=0; slept=0;
    int result=rh3_wait_auto_uicache(223);
    if(result!=0) { fprintf(stderr,"result=%d calls=%d slept=%d kills=%d\n",result,calls,slept,kills); return 20; }
    if(calls!=3) return 21;
    if(kills!=0) return 22;
    if(slept!=2) return 23;
    mode=1; calls=0; kills=0; slept=0;
    if(rh3_wait_auto_uicache(223)!=-ETIMEDOUT || kills!=1 || slept>120) return 3;
    mode=2; calls=0; kills=0; slept=0;
    if(rh3_wait_auto_uicache(223)!=ECHILD || kills!=0) return 4;
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory) / "uicache_wait.c"
            exe = Path(directory) / "uicache_wait.exe"
            src.write_text(prefix + function + suffix, encoding="utf-8")
            result = subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                     str(src), "-o", str(exe)], capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr + f" exit={run.returncode}")


if __name__ == "__main__":
    unittest.main()
