"""Native host checks for the actual exec trace exception-port rollback helper.

No ptrace/Mach task calls or real processes are manipulated on the host.
This tests the rollback primitive separately from the Objective-C daemon.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "BaseBin/libjailbreak/src/roothider/exec_trace.m"


class ExecTraceRollbackTests(unittest.TestCase):
    def test_attach_contract_carries_failure_to_xpc_and_frees_saved_ports(self):
        text = SOURCE.read_text(encoding="utf-8")
        method = text.split("int execTraceProcess(pid_t pid, uint64_t traced)", 1)[1].split(
            "int execTraceCancel(pid_t pid, uint64_t detached)", 1)[0]
        self.assertIn("trace_data->saved_exception_types_count = EXC_TYPES_COUNT;", method)
        self.assertIn("int attachResult = ptrace(PT_ATTACHEXC, pid, NULL, 0);", method)
        self.assertIn("rh3_exec_trace_restore_saved_ports(task, trace_data, portsInstalled)", method)
        self.assertIn("if (!traceAttached)", method)
        self.assertIn("ret = -1;", method)
        self.assertNotIn("int ret = ptrace(PT_ATTACHEXC", method)

    def test_native_restore_release_success_failure_and_no_restore(self):
        compiler = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
        if not compiler:
            self.skipTest("No native C compiler")
        source = SOURCE.read_text(encoding="utf-8")
        method = source[source.index("static int rh3_exec_trace_restore_saved_ports("):
                        source.index("static void finish_process_trace(")]
        stub = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
typedef int kern_return_t;
typedef unsigned mach_port_t;
#define MACH_PORT_NULL 0
#define MACH_PORT_VALID(x) ((x) != 0)
#define KERN_SUCCESS 0
#define EXC_TYPES_COUNT 4
typedef struct { unsigned saved_exception_types_count;
    unsigned saved_masks[4], saved_ports[4], saved_behaviors[4], saved_flavors[4]; } trace_data_t;
static int restores, releases, fail_restore;
static int task_set_exception_ports(unsigned task,unsigned mask,unsigned port,unsigned b,unsigned f) {
    (void)task;(void)mask;(void)port;(void)b;(void)f;
    restores++;return fail_restore && restores==1 ? 5 : KERN_SUCCESS;
}
static int mach_port_deallocate(unsigned task,unsigned port) {
    (void)task;(void)port;releases++;return 0;
}
#define mach_task_self() 1
#define CHECK(x) do {if(!(x)){fprintf(stderr,"failed line %d: %s\n",__LINE__,#x);return 1;}}while(0)
'''
        test = r'''
int main(void) {
    trace_data_t state={.saved_exception_types_count=3,
        .saved_masks={1,2,4},.saved_ports={12,0,13}};
    CHECK(rh3_exec_trace_restore_saved_ports(44,&state,true)==0);
    CHECK(restores==3 && releases==2);
    CHECK(state.saved_ports[0]==0 && state.saved_ports[2]==0);
    restores=releases=0; fail_restore=1;
    state.saved_ports[0]=20;state.saved_ports[1]=21;
    CHECK(rh3_exec_trace_restore_saved_ports(44,&state,true)!=0);
    CHECK(restores==3 && releases==2);
    restores=releases=0;fail_restore=0;
    state.saved_ports[0]=12;
    CHECK(rh3_exec_trace_restore_saved_ports(44,&state,false)==0);
    CHECK(restores==0 && releases==1);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "restore.c"
            exe = Path(d) / "restore.exe"
            p.write_text(stub + method + test, encoding="utf-8")
            b = subprocess.run([compiler, "-std=c11", str(p), "-o", str(exe)], capture_output=True, text=True)
            self.assertEqual(b.returncode, 0, b.stderr)
            r = subprocess.run([str(exe)], capture_output=True, text=True, timeout=8)
            self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
