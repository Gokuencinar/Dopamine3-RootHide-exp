"""Execute RootHide's production plist loader with bounded fake file syscalls.

This covers the launchdhook/systemhook shared configuration reader; malformed
config should never exhaust descriptors inside long-lived processes (PID 1).
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "BaseBin/systemhook/src/common/common.c"


class PlistFileDescriptorSafetyTests(unittest.TestCase):
    def test_config_lookup_rejects_missing_or_non_dictionary_plist(self):
        source = SOURCE.read_text(encoding="utf-8")
        reader = source[source.index("xpc_object_t jbuserconfig_get_value("):
                        source.index("static kSpawnConfig spawn_config_for_executable(")]
        self.assertIn("if (!configDict || xpc_get_type(configDict) != XPC_TYPE_DICTIONARY) return NULL;", reader)
        self.assertLess(reader.index("if (!configDict || xpc_get_type(configDict) != XPC_TYPE_DICTIONARY)"),
                        reader.index("return xpc_dictionary_get_value(configDict, key)"))

    def test_loader_closes_descriptor_on_every_path_and_bounds_untrusted_size(self):
        compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not compiler:
            self.skipTest("Native compiler unavailable")
        source = SOURCE.read_text(encoding="utf-8")
        fn = source[source.index("xpc_object_t xpc_object_from_plist("):
                    source.index("xpc_object_t jbuserconfig_get_value(")]
        prefix = r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef O_CLOEXEC
#define O_CLOEXEC 0x40000
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0x4000
#endif
#define PROT_READ 1
#define MAP_PRIVATE 2
#define MAP_FAILED ((void *)(intptr_t)-1)
#ifndef S_IFDIR
#define S_IFDIR _S_IFDIR
#endif
#ifndef S_IFREG
#define S_IFREG _S_IFREG
#endif
typedef void *xpc_object_t;
static struct {int opens, closes, stats, maps, unmaps, decodes, failStat, failMap;
               int nonregular; off_t size;} state;
static char buffer[128];
static int seenFlags;
static void reset(void) {state=(typeof(state)){0};state.size=16;}
static int test_open(const char *path, int flags) {
    seenFlags=flags;
    state.opens++; return 42;
}
static int test_fstat(int fd, struct stat *st) {
    state.stats++; if (state.failStat) return -1;
    st->st_mode=state.nonregular?S_IFDIR:S_IFREG;st->st_size=state.size;return 0;
}
static int test_close(int fd) {state.closes++;return 0;}
static void *test_mmap(void *p,size_t len,int prot,int flags,int fd,off_t off) {
    state.maps++;return state.failMap?MAP_FAILED:buffer;
}
static int test_munmap(void *p,size_t size) {state.unmaps++;return 0;}
static xpc_object_t test_decode(const void *p,size_t len) {
    state.decodes++;return (xpc_object_t)buffer;
}
#define open test_open
#define fstat test_fstat
#define close test_close
#define mmap test_mmap
#define munmap test_munmap
#define xpc_create_from_plist test_decode
#define MAP_FILE 0
#define CHECK(x) do {if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);return 1;}}while(0)
'''
        cases = r'''
int main(void) {
    reset();CHECK(xpc_object_from_plist("/root/config.plist") == buffer);
    CHECK(state.opens==1 && state.closes==1 && state.maps==1 && state.unmaps==1 && state.decodes==1);
    CHECK((seenFlags & (O_NONBLOCK|O_CLOEXEC)) == (O_NONBLOCK|O_CLOEXEC));
    reset();state.failStat=1;CHECK(xpc_object_from_plist("p")==NULL);
    CHECK(state.opens==1 && state.closes==1 && state.maps==0 && state.decodes==0);
    reset();state.failMap=1;CHECK(xpc_object_from_plist("p")==NULL);
    CHECK(state.opens==1 && state.closes==1 && state.maps==1 && state.decodes==0);
    reset();state.size=0;CHECK(xpc_object_from_plist("p")==NULL);
    CHECK(state.closes==1 && state.maps==0);
    reset();state.size=-1;CHECK(xpc_object_from_plist("p")==NULL);
    CHECK(state.closes==1 && state.maps==0);
    reset();state.size=8*1024*1024;CHECK(xpc_object_from_plist("p")==NULL);
    CHECK(state.closes==1 && state.maps==0);
    reset();state.nonregular=1;CHECK(xpc_object_from_plist("p")==NULL);
    CHECK(state.closes==1 && state.maps==0);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "plist.c"
            executable = Path(d) / "plist.exe"
            path.write_text(prefix + fn + cases, encoding="utf-8")
            build = subprocess.run([compiler, "-std=gnu11", str(path), "-o", str(executable)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=8)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
