"""Native regression: a failed _NSGetExecutablePath cannot trigger PID1 re-exec.

Extracts the production hook's branch, then compiles it with a mocked dyld
API. This does NOT prove iOS launchd, trustcache or systemhook execution.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "BaseBin/launchdhook/src/spawn_hook.c"


def native_preflight_result(source: str) -> tuple[int, str]:
    start = source.index("int __posix_spawn_hook(pid_t")
    start = source.index("\tif (path) {", start)
    end = source.index("\t\t\tbool rootHideHandoff", start)
    preflight = source[start:end]
    c_source = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static int fake_result;
static int _NSGetExecutablePath(char *buf, uint32_t *size) {
    (void)size;
    // A failed API may still leave a matching partial/whole buffer.
    // Its contents cannot authenticate the current executable.
    strcpy(buf, "/sbin/launchd");
    return fake_result;
}
static int is_reexec(const char *path) {
''' + preflight + r'''
        return 1;
    }
}
return 0;
}
int main(void) {
    fake_result = 0;
    if (!is_reexec("/sbin/launchd")) return 1;
    if (is_reexec("/usr/libexec/xpcproxy")) return 2;
    fake_result = -1;
    if (is_reexec("/sbin/launchd")) return 3;
    if (is_reexec("/usr/libexec/xpcproxy")) return 4;
    if (is_reexec(NULL)) return 5;
    return 0;
}
'''
    compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
    if not compiler:
        raise unittest.SkipTest("No native C compiler")
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "preflight.c"
        binary = Path(temp) / "preflight.exe"
        path.write_text(c_source, encoding="utf-8")
        built = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", str(path), "-o", str(binary)],
                               capture_output=True, text=True, timeout=25)
        if built.returncode:
            raise AssertionError(built.stderr)
        run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        return run.returncode, run.stderr


class PID1SelfSpawnPreflight(unittest.TestCase):
    def test_failed_dyld_path_lookup_does_not_trigger_userspace_reexec(self):
        result, stderr = native_preflight_result(SOURCE.read_text(encoding="utf-8"))
        self.assertEqual(result, 0, stderr)


if __name__ == "__main__":
    unittest.main()
