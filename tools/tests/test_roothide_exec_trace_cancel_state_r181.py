"""Production execTrace cancel state rollback, tested with host C stubs."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SRC = Path(__file__).resolve().parents[2] / "BaseBin/libjailbreak/src/roothider/exec_trace.m"


class CancelStateTests(unittest.TestCase):
    def test_actual_helper_preserves_state_after_failed_signal(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("No host C compiler")
        src = SRC.read_text(encoding="utf-8")
        helper = src[src.index("static void rh3_exec_trace_revert_unsent_cancel("):
                     src.index("static int rh3_exec_trace_restore_saved_ports(")]
        code = r'''
#include <stdbool.h>
#include <stdint.h>
typedef struct {bool cancelled; uint64_t detached_flag_addr;} trace_data_t;
'''+ helper + r'''
int main(void) {
    trace_data_t record={.cancelled=true,.detached_flag_addr=301};
    rh3_exec_trace_revert_unsent_cancel(&record,false,100,-1);
    if(record.cancelled || record.detached_flag_addr!=100) return 1;
    record.cancelled=true;record.detached_flag_addr=301;
    rh3_exec_trace_revert_unsent_cancel(&record,false,100,0);
    if(!record.cancelled || record.detached_flag_addr!=301) return 2;
    record.cancelled=true;record.detached_flag_addr=400;
    rh3_exec_trace_revert_unsent_cancel(&record,true,301,-1);
    if(!record.cancelled || record.detached_flag_addr!=301) return 3;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            f = Path(directory) / "cancel.c"
            binary = Path(directory) / "cancel.exe"
            f.write_text(code, encoding="utf-8")
            result = subprocess.run([cc, "-std=c11", str(f), "-o", str(binary)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_cancel_entrypoint_uses_helper_after_signal_delivery(self):
        s = SRC.read_text(encoding="utf-8")
        body = s.split("int execTraceCancel(pid_t pid, uint64_t detached)", 1)[1]
        self.assertIn("rh3_exec_trace_revert_unsent_cancel(trace_data,", body)
        self.assertIn("ret = kill(pid, SIGTRAP);", body)
        self.assertLess(body.index("ret = kill(pid, SIGTRAP);"),
                        body.index("rh3_exec_trace_revert_unsent_cancel(trace_data,"))


if __name__ == "__main__":
    unittest.main()
