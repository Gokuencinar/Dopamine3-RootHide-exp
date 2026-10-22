"""Host-executed lifecycle contract for the one-shot NOTE_EXEC cancel race.

These tests exercise the exact inline decision helper used by the Objective-C
daemon, not the iOS kernel's kevent machinery or device execution.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "BaseBin/libjailbreak/src/roothider/exec_patch.h"
SOURCE = ROOT / "BaseBin/libjailbreak/src/roothider/exec_patch.m"


class ExecPatchCancel(unittest.TestCase):
    def test_watch_deletion_decisions_with_real_compiled_helper(self):
        compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not compiler:
            self.skipTest("Host C compiler unavailable")
        program = r'''
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include "exec_patch.h"
int main(void) {
    // The watch exists and was successfully removed.
    if (!rh3_exec_patch_watch_cancelled(0, 0)) return 1;
    // The one-shot NOTE_EXEC/NOTE_EXIT watch was already consumed.
    if (!rh3_exec_patch_watch_cancelled(-1, ENOENT)) return 2;
    // Fatal/unknown errors must not pretend cancellation was successful.
    if (rh3_exec_patch_watch_cancelled(-1, EBADF)) return 3;
    if (rh3_exec_patch_watch_cancelled(-1, EINVAL)) return 4;
    if (rh3_exec_patch_watch_cancelled(-1, ESRCH)) return 5;
    if (rh3_exec_patch_watch_cancelled(1, 0)) return 6;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cancel.c"
            executable = Path(directory) / "cancel.exe"
            path.write_text(program, encoding="utf-8")
            compile_result = subprocess.run(
                [compiler, str(path), "-I", str(HEADER.parent), "-o", str(executable)],
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            test_result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
            self.assertEqual(test_result.returncode, 0, test_result.stderr)

    def test_cancel_retries_interrupt_and_never_strands_its_own_record_on_enoent(self):
        source = SOURCE.read_text(encoding="utf-8")
        cancel = source.split("int spawnExecPatchDel(int pid)", 1)[1].split("return ret;", 1)[0]
        self.assertIn("while (deleted == -1 && errno == EINTR)", cancel)
        self.assertIn("rh3_exec_patch_watch_cancelled(deleted, deleteError)", cancel)
        self.assertLess(cancel.index("rh3_exec_patch_watch_cancelled"),
                        cancel.index("[gExecPatchArray removeObjectForKey:@(pid)]"))
        self.assertIn("__block int ret = 0", cancel)
        self.assertIn("return -1", cancel)
        self.assertNotIn('JBLogError("[spawnExecPatchDel] no record', cancel)


if __name__ == "__main__":
    unittest.main()
