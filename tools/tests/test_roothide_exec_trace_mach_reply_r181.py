"""Execute production Mach exception reply/rights cleanup with failure injection.

All mocked ports live in an isolated host C process; no actual Mach operations.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SRC = Path(__file__).resolve().parents[2] / "BaseBin/libjailbreak/src/roothider/exec_trace.m"


class MachReplyLifecycleTests(unittest.TestCase):
    def test_native_success_and_failed_reply_release_received_rights_once(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("C compiler not available")
        source = SRC.read_text(encoding="utf-8")
        function = source[source.index("static mach_msg_return_t rh3_exec_trace_reply_and_destroy("):
                          source.index("static void* exception_server(")]
        declarations = r'''
#include <stdint.h>
#include <stdio.h>
typedef uint32_t mach_port_t;
typedef uint32_t mach_msg_bits_t;
typedef int mach_msg_return_t;
typedef struct {
  mach_msg_bits_t msgh_bits;
  uint32_t msgh_size;
  mach_port_t msgh_remote_port;
  mach_port_t msgh_local_port;
  uint32_t msgh_id;
} mach_msg_header_t;
typedef struct {mach_msg_header_t Head;} __Reply__mach_exception_raise_t;
#define MACH_PORT_NULL 0
#define MACH_MSG_SUCCESS 0
#define MACH_SEND_MSG 1
#define MACH_MSG_OPTION_NONE 0
#define MACH_MSG_TIMEOUT_NONE 0
#define MACH_SEND_INVALID_DEST 0x10000003
#define MACH_SEND_TIMED_OUT 0x10000004
#define MACH_SEND_INTERRUPTED 0x10000007
#define MACH_SEND_INVALID_RIGHT 0x1000000a
#define MACH_SEND_TOO_LARGE 0x1000000e
#define MACH_MSGH_BITS_REMOTE(x) ((x)&0xff)
#define MACH_MSGH_BITS(r,l) ((r)|((l)<<8))
static int message_sends, message_destroys, error_code, wrong_destroy_port;
static mach_port_t destination, destroyed_port, expected_destroyed_port;
static mach_msg_return_t mach_msg(mach_msg_header_t *m,int options,unsigned send,
                  unsigned rcv,mach_port_t name,int timeout,mach_port_t notify) {
 (void)options;(void)send;(void)rcv;(void)name;(void)timeout;(void)notify;
 message_sends++;destination=m->msgh_remote_port;
 return error_code;
}
static void mach_msg_destroy(mach_msg_header_t *m) {
 message_destroys++; destroyed_port=m->msgh_remote_port;
 if (destroyed_port!=expected_destroyed_port) wrong_destroy_port=1;
}
#define CHECK(x) do {if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);return 1;}}while(0)
'''
        cases = r'''
int main(void) {
 mach_msg_header_t request={.msgh_bits=19,.msgh_remote_port=17,.msgh_id=2400};
 __Reply__mach_exception_raise_t reply={0};
 CHECK(rh3_exec_trace_reply_and_destroy(&request,&reply)==MACH_MSG_SUCCESS);
 CHECK(message_sends==1 && message_destroys==1 && !wrong_destroy_port);
 CHECK(destination==17 && destroyed_port==0 && request.msgh_remote_port==0);
 CHECK(reply.Head.msgh_id==2500 && reply.Head.msgh_remote_port==17);
 const int recoverable[]={MACH_SEND_INVALID_DEST,MACH_SEND_TIMED_OUT,MACH_SEND_INTERRUPTED};
 for(unsigned i=0;i<sizeof(recoverable)/sizeof(recoverable[0]);i++) {
   request.msgh_remote_port=17;error_code=recoverable[i];expected_destroyed_port=17;
   CHECK(rh3_exec_trace_reply_and_destroy(&request,&reply)==error_code);
   CHECK(destination==17 && destroyed_port==17 && request.msgh_remote_port==17);
 }
 const int nonrecoverable[]={MACH_SEND_INVALID_RIGHT,MACH_SEND_TOO_LARGE};
 for(unsigned i=0;i<sizeof(nonrecoverable)/sizeof(nonrecoverable[0]);i++) {
   request.msgh_remote_port=17;error_code=nonrecoverable[i];expected_destroyed_port=0;
   CHECK(rh3_exec_trace_reply_and_destroy(&request,&reply)==error_code);
   CHECK(destination==17 && destroyed_port==0 && request.msgh_remote_port==0);
 }
 CHECK(message_sends==6 && message_destroys==6 && !wrong_destroy_port);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            c = Path(folder) / "reply.c"
            exe = Path(folder) / "reply.exe"
            c.write_text(declarations + function + cases, encoding="utf-8")
            built = subprocess.run([cc, "-std=c11", str(c), "-o", str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=7)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_receiver_never_skips_reply_on_unknown_pid_or_dereferences_missing_code(self):
        source = SRC.read_text(encoding="utf-8")
        server = source.split("static void* exception_server(", 1)[1].split(
            "int execTraceProcess(pid_t pid, uint64_t traced)", 1)[0]
        self.assertIn("reply.RetCode = KERN_FAILURE;", server)
        self.assertIn("goto send_reply;", server)
        self.assertIn("send_reply:", server)
        self.assertIn("rh3_exec_trace_reply_and_destroy(msg, &reply)", server)
        self.assertIn("request->codeCnt >= 2", server)

    def test_thread_state_diagnostics_never_abandon_trace_before_handling_signal(self):
        source = SRC.read_text(encoding="utf-8")
        server = source.split("static void* exception_server(", 1)[1].split(
            "int execTraceProcess(pid_t pid, uint64_t traced)", 1)[0]
        state_section = server.split("kr = thread_get_state(", 1)[1].split("[trace_data_lock lock]", 1)[0]
        self.assertIn("kr == KERN_SUCCESS && threadStateCount == ARM_THREAD_STATE64_COUNT", state_section)
        self.assertNotIn("goto send_reply;", state_section)
        self.assertNotIn("reply.RetCode = KERN_FAILURE;", state_section)


if __name__ == "__main__":
    unittest.main()
