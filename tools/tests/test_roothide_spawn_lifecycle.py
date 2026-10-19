from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class SpawnLifecycleTests(unittest.TestCase):
    def test_production_routes_spawn_and_exec_through_daemon(self):
        common = (ROOT/'BaseBin/systemhook/src/common/common.c').read_text(encoding='utf-8')
        main = (ROOT/'BaseBin/systemhook/src/main.c').read_text(encoding='utf-8')
        client = (ROOT/'BaseBin/libjailbreak/src/jbclient_roothide.c').read_text(encoding='utf-8')
        server = (ROOT/'BaseBin/jailbreakd/src/server.m').read_text(encoding='utf-8')
        self.assertIn('rh3_spawn_patched(pid ?: pidOut', common)
        self.assertIn('bool rootHide = getpid() != 1 && path', common)
        self.assertIn('&& !rootHide)', common)
        self.assertIn('posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETEXEC)', main)
        for action in ('JBD_MSG_SPAWN_PATCH_CHILD', 'JBD_MSG_SPAWN_EXEC_START', 'JBD_MSG_SPAWN_EXEC_CANCEL'):
            self.assertIn(action, client)
        self.assertIn('xpc_get_type(value) == XPC_TYPE_INT64', client)
        self.assertIn('if(ppid == clientPid)', server)

    @unittest.skipUnless(sys.platform == 'darwin', 'Suspended spawn requires Darwin')
    def test_real_suspended_child_and_failure_ordering(self):
        source = r'''
#include "roothide_spawn.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
extern char **environ;
static int channel[2], patches, starts, cancels, calls;
static bool reject;
static int patch(pid_t pid, bool resume) {
    patches++;
    char ch;
    if (read(channel[0], &ch, 1) != -1 || errno != EAGAIN) return -1;
    if (reject) return -1;
    return resume ? kill(pid, SIGCONT) : 0;
}
#define CHECK(c, n) do { if (!(c)) { fprintf(stderr, "case %d errno %d\n", n, errno); return n; } } while (0)
int main(void) {
    CHECK(pipe(channel) == 0, 1);
    fcntl(channel[0], F_SETFL, O_NONBLOCK);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, channel[1], 8);
    posix_spawnattr_t attributes;
    CHECK(posix_spawnattr_init(&attributes) == 0, 2);
    int (^spawn)(pid_t *) = ^int(pid_t *pid) {
        calls++;
        char *args[] = {"sh", "-c", "printf x >&8", NULL};
        return posix_spawn(pid, "/bin/sh", &actions, &attributes, args, environ);
    };
    int (^start)(bool) = ^int(bool resume) { starts++; return 0; };
    int (^cancel)(void) = ^int(void) { cancels++; return 0; };
    pid_t pid = 0;
    CHECK(rh3_spawn_patched(&pid, &attributes, false, spawn, patch, start, cancel) == 0, 3);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, 4);
    char ch;
    CHECK(read(channel[0], &ch, 1) == 1 && ch == 'x' && patches == 1, 5);
    short flags = -1;
    CHECK(posix_spawnattr_getflags(&attributes, &flags) == 0 && flags == 0, 6);
    // A caller's suspended flag must remain set; the daemon must not resume.
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_START_SUSPENDED);
    CHECK(rh3_spawn_patched(&pid, &attributes, false, spawn, patch, start, cancel) == 0, 7);
    CHECK(read(channel[0], &ch, 1) == -1 && errno == EAGAIN, 8);
    CHECK(posix_spawnattr_getflags(&attributes, &flags) == 0 && flags == POSIX_SPAWN_START_SUSPENDED, 9);
    kill(pid, SIGCONT); waitpid(pid, &status, 0); read(channel[0], &ch, 1);
    posix_spawnattr_setflags(&attributes, 0);
    // Patch rejection kills/reaps only the newly created child.
    reject = true;
    CHECK(rh3_spawn_patched(&pid, &attributes, false, spawn, patch, start, cancel) == EIO && pid == 0, 10);
    CHECK(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD, 11);
    reject = false;
    // Failed SETEXEC must cancel its watcher and restore caller flags.
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETEXEC);
    CHECK(rh3_spawn_patched(NULL, &attributes, false, ^int(pid_t *p) { return ENOENT; }, patch, start, cancel) == ENOENT, 12);
    CHECK(starts == 1 && cancels == 1, 13);
    CHECK(posix_spawnattr_getflags(&attributes, &flags) == 0 && flags == POSIX_SPAWN_SETEXEC, 14);
    CHECK(rh3_spawn_patched(NULL, &attributes, false, ^int(pid_t *p) { return EINVAL; }, patch,
        ^int(bool r) { return -1; }, cancel) == EIO, 15);
    CHECK(cancels == 1 && calls == 3, 16);
    // DriverKit is passed through without patching or SETEXEC registration.
    CHECK(rh3_spawn_patched(NULL, &attributes, true, ^int(pid_t *p) { return ENOTSUP; }, patch, start, cancel) == ENOTSUP, 17);
    CHECK(starts == 1 && cancels == 1 && patches == 3, 18);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    close(channel[0]); close(channel[1]);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'spawn.c'
            binary = Path(directory)/'spawn'
            path.write_text(source, encoding='utf-8')
            result = subprocess.run(['xcrun', 'clang', '-fblocks', '-I',
                str(ROOT/'BaseBin/systemhook/src/common'), str(path), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
