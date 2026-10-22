"""Regression for nonfatal RootHide spawn/configuration preflight cases.

The array probe compiles and EXECUTES the production blacklist function with a
minimal XPC stub. It is not a Darwin/launchd, SSH, or hardware test.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "BaseBin/systemhook/src/common/common.c"
ENV = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m"
EXEC_PATCH = ROOT / "BaseBin/libjailbreak/src/roothider/exec_patch.m"
DAEMON = ROOT / "BaseBin/launchdhook/src/daemon_hook.m"
SERVER = ROOT / "BaseBin/jailbreakd/src/server.m"


class SpawnPreflightGuards(unittest.TestCase):
    def test_invalid_blacklist_entry_is_ignored_without_crash(self):
        compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        if not compiler:
            self.skipTest("Host C compiler not found")
        source = COMMON.read_text(encoding="utf-8")
        function = source.split("static kSpawnConfig spawn_config_for_executable(", 1)[1]
        function = "static kSpawnConfig spawn_config_for_executable(" + function.split(
            "// 1. Ensure the binary", 1
        )[0]
        stub = r'''
#include <stddef.h>
#include <string.h>
#include <stdio.h>
typedef void *xpc_object_t;
typedef int kSpawnConfig;
enum { kSpawnConfigTrust = 1, kSpawnConfigInject = 2 };
#define XPC_TYPE_ARRAY ((void*)1)
static const char *entries[2];
static int count, enabled;
static xpc_object_t jbuserconfig_get_value(const char *key) {
    return enabled && !strcmp(key, "ProcessBlacklist") ? (void*)2 : NULL;
}
static void *xpc_get_type(xpc_object_t value) { return value == (void*)2 ? XPC_TYPE_ARRAY : NULL; }
static size_t xpc_array_get_count(xpc_object_t value) { return (size_t)count; }
static const char *xpc_array_get_string(xpc_object_t value, size_t index) { return entries[index]; }
#define CHECK(c) do { if (!(c)) return __LINE__; } while (0)
'''
        cases = r'''
int main(void) {
    char *args[] = {"sshd", NULL};
    const char *ssh = "/private/preboot/test/usr/sbin/sshd";
    enabled = 0;
    CHECK(spawn_config_for_executable(ssh, args) == (kSpawnConfigInject | kSpawnConfigTrust));
    enabled = 1; count = 1; entries[0] = NULL; // malformed non-string XPC entry
    CHECK(spawn_config_for_executable(ssh, args) == (kSpawnConfigInject | kSpawnConfigTrust));
    count = 2; entries[1] = ssh;
    CHECK(spawn_config_for_executable(ssh, args) == kSpawnConfigTrust);
    CHECK(spawn_config_for_executable("/System/Library/Frameworks/GSS.framework/Helpers/GSSCred", args) == 0);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "spawn_config_test.c"
            exe = Path(directory) / "spawn_config_test.exe"
            path.write_text(stub + function + cases, encoding="utf-8")
            compiled = subprocess.run([compiler, str(path), "-o", str(exe)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            observed = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(observed.returncode, 0, observed.stderr)

    def test_persona_fix_only_runs_after_successful_spawn(self):
        source = COMMON.read_text(encoding="utf-8")
        self.assertIn("r == 0 && childPid > 0 && (personaFixUid == 0 || personaFixGid == 0)", source)
        self.assertNotIn("personaFixUid == 0 || personaFixGid == 0 && childPid != -1", source)

    def test_preboot_never_requires_keygen_with_existing_host_key(self):
        source = ENV.read_text(encoding="utf-8")
        preflight = source.split("int (^sshPreflight)(void) = ^int {", 1)[1].split(
            "int result = installerPhase ? sshPreflight()", 1
        )[0]
        self.assertIn("for (NSString *binary in @[sshdPath])", preflight)
        self.assertIn('@"usr", @"usr/sbin"', preflight)
        self.assertIn('O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC', preflight)
        repair = source.split("if (needsKey && !allowKeyGeneration)", 1)[1].split(
            "if (!installerPhase)", 1
        )[0]
        self.assertLess(repair.index("if (needsKey)"), repair.index("lstat(keygenPath.fileSystemRepresentation"))
        self.assertLess(repair.index("lstat(keygenPath.fileSystemRepresentation"),
                        repair.index("rh3RunCommand:keygenPath"))
        commit = source.split("int (^sshCommit)(void) = ^int {", 1)[1].split(
            "result = installerPhase ? sshCommit()", 1
        )[0]
        self.assertIn('for (NSString *suffix in @[@"usr", @"usr/sbin", @"etc", @"etc/ssh"])', commit)

    def test_exec_event_wait_retries_only_eintr(self):
        source = EXEC_PATCH.read_text(encoding="utf-8")
        section = source.split("void event_handler(int kq)", 1)[1].split("void initExecPatch()", 1)[0]
        self.assertIn("while (ret == -1 && errno == EINTR)", section)
        self.assertIn("assert(ret == 1)", section)

    def test_launchd_paths_lookup_handles_null_and_repeated_paths(self):
        compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        if not compiler:
            self.skipTest("Host C compiler not found")
        code = DAEMON.read_text(encoding="utf-8")
        body = code.split("static bool rh3_xpc_paths_contains(", 1)[1].split(
            "xpc_object_t xpc_dictionary_get_value_hook", 1
        )[0]
        function = "static bool rh3_xpc_paths_contains(" + body
        stub = r'''
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
typedef void *xpc_object_t;
#define XPC_TYPE_ARRAY ((void*)1)
static const char *entries[] = {"/other", NULL, "/jbroot/basebin/LaunchDaemons"};
static void *xpc_get_type(xpc_object_t obj) { return obj == (void*)3 ? XPC_TYPE_ARRAY : NULL; }
static size_t xpc_array_get_count(xpc_object_t obj) { return sizeof(entries)/sizeof(entries[0]); }
static const char *xpc_array_get_string(xpc_object_t obj, size_t i) { return entries[i]; }
'''
        cases = r'''
int main(void) {
    xpc_object_t paths = (void*)3;
    if (rh3_xpc_paths_contains(NULL, "/other")) return 1;
    if (rh3_xpc_paths_contains(paths, NULL)) return 2;
    if (rh3_xpc_paths_contains((void*)2, "/other")) return 3;
    if (!rh3_xpc_paths_contains(paths, "/jbroot/basebin/LaunchDaemons")) return 4;
    if (rh3_xpc_paths_contains(paths, "/jbroot/Library/LaunchDaemons")) return 5;
    return 0;
}
'''
        self.assertIn("if (!rh3_xpc_paths_contains(origXvalue, basebin))", code)
        self.assertIn("if (!rh3_xpc_paths_contains(origXvalue, packages))", code)
        self.assertIn("if (origXvalue && xpc_get_type(origXvalue) == XPC_TYPE_DICTIONARY)", code)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "paths.c"
            exe = Path(directory) / "paths.exe"
            path.write_text(stub + function + cases, encoding="utf-8")
            compiled = subprocess.run([compiler, str(path), "-o", str(exe)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_patch_daemon_propagates_failed_resume(self):
        server = SERVER.read_text(encoding="utf-8")
        patch_child = server.split("case JBD_MSG_SPAWN_PATCH_CHILD:", 1)[1].split(
            "case JBD_MSG_SPAWN_EXEC_START:", 1
        )[0]
        self.assertIn("resume && kill(pid, SIGCONT) != 0", patch_child)
        self.assertIn("result = -1", patch_child)
        self.assertLess(patch_child.index("result = -1"),
                        patch_child.index('xpc_dictionary_set_int64(reply, "result", result)'))

    def test_spawn_failure_child_reap_has_deadline(self):
        lifecycle = (ROOT / "BaseBin/systemhook/src/common/roothide_spawn.h").read_text(encoding="utf-8")
        self.assertIn("waitpid(child, NULL, WNOHANG)", lifecycle)
        self.assertIn("attempt < 20", lifecycle)
        self.assertIn("if (waited < 0 && errno != EINTR) break", lifecycle)
        self.assertNotIn("waitpid(child, NULL, 0)", lifecycle)


if __name__ == "__main__":
    unittest.main()
