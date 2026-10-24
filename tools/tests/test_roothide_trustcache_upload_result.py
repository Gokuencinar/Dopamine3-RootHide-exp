"""Exercise production trust_signatures() result propagation in native host C.

The private dyld's late trust may call this server function when the kernel
rejects a dependent library. Trustcache upload failure must not be reported
as success or followed by a signature attach.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SIGNATURES = ROOT / "BaseBin/libjailbreak/src/signatures.c"


class TrustcacheUploadResultTests(unittest.TestCase):
    def test_native_production_tail_propagates_upload_and_attach_errors(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("C compiler unavailable")
        source = SIGNATURES.read_text(encoding="utf-8")
        function = source[source.index("int trust_signatures("):]
        start = function.index("if (cdhashesCount > 0) {")
        end = function.index("return r;", start) + len("return r;")
        production_tail = function[start:end]
        harness = r'''
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
struct siginfo { int signature; };
static int simulatedTrustResult = 0;
static int simulatedAttachResult = 0;
static int attachCount = 0;
static int jb_trustcache_add_cdhashes(void *hashes, uint32_t count) {
    (void)hashes; (void)count; return simulatedTrustResult;
}
static int fd_attach_signature(int fd, int *signature) {
    (void)fd; (void)signature; attachCount++; return simulatedAttachResult;
}
static int test_production_tail(int trust, int attach) {
    int fd = 0;
    uint32_t cdhashesCount = 1;
    uint32_t sigInfosToAttachCount = 1;
    void *cdhashes = malloc(20);
    struct siginfo *item = calloc(1,sizeof(*item));
    struct siginfo **sigInfosToAttach = malloc(sizeof(*sigInfosToAttach));
    if (!cdhashes || !item || !sigInfosToAttach) return -99;
    sigInfosToAttach[0] = item;
    simulatedTrustResult = trust;
    simulatedAttachResult = attach;
    attachCount = 0;
'''
        checks = r'''
}
int main(void) {
    int result = test_production_tail(-7, 0);
    if (result != -7 || attachCount != 0) return 1;
    result = test_production_tail(0, -13);
    if (result != -13 || attachCount != 1) return 2;
    result = test_production_tail(0, 0);
    if (result != 0 || attachCount != 1) return 3;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp) / "trust_return.c"
            exe = Path(temp) / "trust_return.exe"
            src.write_text(harness + production_tail + checks, encoding="utf-8")
            compiled = subprocess.run([cc, "-std=c11", str(src), "-o", str(exe)],
                                      capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            run = subprocess.run([str(exe)], capture_output=True,
                                 text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr +
                             f" (native failure #{run.returncode})")


if __name__ == "__main__":
    unittest.main()
