"""Real macOS XPC roundtrip through the port receiver and production dispatcher.

This tests transport/routing and permissions, not iOS kernel primitives.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / 'BaseBin/libjailbreak/src'


@unittest.skipUnless(sys.platform == 'darwin', 'native Mach/XPC runtime requires macOS')
class JailbreakdBootstrap(unittest.TestCase):
    def test_roundtrip_preserves_audit_token_and_permission_rejection(self):
        prelude = r'''
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <mach/mach.h>
#include <bsm/libbsm.h>
#include <xpc/xpc.h>
extern uid_t audit_token_to_euid(audit_token_t);
// Unused kernel-signature/hook interfaces are not linked into this host test.
#define SIGNATURES_H
struct siginfo { int unused; };
#define HOOK_D
#define LJB_UTIL_H
extern void xpc_dictionary_set_mach_send(xpc_object_t, const char *, mach_port_t);
extern mach_port_t xpc_dictionary_copy_mach_send(xpc_object_t, const char *);
'''
        harness = r'''
#include <pthread.h>
#include "roothider/jailbreakd_bootstrap.h"
static int calls = 0, permissions = 0, received = -99;
static bool deny = false;
static bool allowed(audit_token_t token) {
    permissions++;
    return !deny && audit_token_to_euid(token) == geteuid();
}
static int twice(void *value, void *b, void *c, void *d, void *e, void *f, void *g, void *h) {
    calls++;
    return (int)(uintptr_t)value * 2;
}
static struct jbserver_domain domain = {
    .permissionHandler = allowed,
    .actions = {
        { .handler = twice, .args = (jbserver_arg[]){
            {"value", JBS_TYPE_UINT64, false}, {NULL, 0, false}} },
        { .handler = NULL },
    }
};
static struct jbserver_impl server = {.maxDomain = 1, .domains = (struct jbserver_domain *[]){&domain, NULL}};
static xpc_object_t request(void) {
    xpc_object_t msg = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(msg, "jb-domain", 1);
    xpc_dictionary_set_uint64(msg, "action", 1);
    xpc_dictionary_set_uint64(msg, "value", 23);
    xpc_dictionary_set_uint64(msg, "uid", 0); // Must not replace the audit token.
    return msg;
}
static void *receive_one(void *arg) {
    xpc_object_t msg = NULL;
    if (xpc_pipe_receive((mach_port_t)(uintptr_t)arg, &msg)) { received = -98; return NULL; }
    received = RH3DispatchBootstrapMessage(&server, msg);
    xpc_release(msg);
    return NULL;
}
int main(void) {
    xpc_object_t msg = request();
    deny = true;
    if (RH3DispatchBootstrapMessage(&server,msg) != -2 || calls || permissions != 1) return 1;
    if (RH3DispatchBootstrapMessage(NULL,msg) != -1 || calls) return 2;
    xpc_dictionary_set_uint64(msg,"jb-domain",0);
    if (RH3DispatchBootstrapMessage(&server,msg) != -1 || calls) return 3;
    xpc_release(msg);
    msg = xpc_string_create("invalid");
    if (RH3DispatchBootstrapMessage(&server,msg) != -1 || calls) return 4;
    xpc_release(msg);
    deny = false; permissions = 0;
    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&port)) return 5;
    if (mach_port_insert_right(mach_task_self(),port,port,MACH_MSG_TYPE_MAKE_SEND)) return 6;
    pthread_t thread;
    if (pthread_create(&thread,NULL,receive_one,(void *)(uintptr_t)port)) return 7;
    xpc_object_t pipe = xpc_pipe_create_from_port(port,0), reply = NULL;
    if (!pipe) return 8;
    msg = request();
    if (xpc_pipe_routine(pipe,msg,&reply) || !reply) return 9;
    if (xpc_dictionary_get_int64(reply,"result") != 46) return 10;
    pthread_join(thread,NULL);
    if (received || calls != 1 || permissions != 1) return 11;
    xpc_release(reply); xpc_release(msg); xpc_release(pipe);
    mach_port_destroy(mach_task_self(),port);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'prelude.h').write_text(prelude, encoding='utf-8')
            (base / 'main.c').write_text(harness, encoding='utf-8')
            command = ['xcrun', 'clang', '-fblocks', '-include', str(base / 'prelude.h'),
                       '-I', str(LIB), '-I', str(ROOT / 'BaseBin/_external/include'),
                       str(base / 'main.c'), str(LIB / 'jbserver.c'), '-lbsm', '-o', str(base / 'test')]
            built = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            ran = subprocess.run([str(base / 'test')], capture_output=True, text=True, timeout=20)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
