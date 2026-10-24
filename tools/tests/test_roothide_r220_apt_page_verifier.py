"""Execute the native full-page trust gate with a fake, bounded Mach-O backend.

The fixture supplies calculated page hashes independently of the stored
CodeDirectory slots, so a corrupted page *after* page zero is detectable.
No iPhone or installed bootstrap is touched.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WRITER = (ROOT / "BaseBin/libjailbreak/src/roothider/recdhash.m").read_text()
WALKER = (ROOT / "BaseBin/libjailbreak/src/roothider/signatures.m").read_text()


class AptSignedPagesTests(unittest.TestCase):
    def test_actual_bundled_libgnutls_rejects_mutated_second_signed_page(self):
        from test_roothide_apt_bootstrap_macho import code_directories, valid_code_pages
        tar = shutil.which("tar")
        archive = ROOT / "Application/Dopamine/Resources/roothide_bootstrap_1900.tar.zst"
        if not tar or not archive.is_file():
            self.skipTest("Bundled bootstrap or tar unavailable")
        output = subprocess.run([tar, "-xOf", str(archive),
                                 "./usr/lib/libgnutls.30.dylib"],
                                capture_output=True, timeout=40)
        self.assertEqual(output.returncode, 0, output.stderr[:200])
        data = bytearray(output.stdout)
        signatures = code_directories(data)
        self.assertTrue(signatures)
        self.assertTrue(all(valid_code_pages(data, cd) for cd in signatures))
        data[4096 + 42] ^= 0x80
        self.assertFalse(all(valid_code_pages(data, cd) for cd in signatures))

    def test_each_signed_code_page_is_checked_before_cached_hash_shortcut(self):
        native = WALKER.split("isAdhocSigned = csd_superblob_is_adhoc_signed(decodedSuperblob);", 1)[1]
        self.assertLess(native.index("rh3_code_directory_pages_match(macho, best)"),
                        native.index("is_cdhash_trustcached(cdhash)"))
        self.assertIn("!*failed && !is_cdhash_trustcached(cdhash)", native)
        writer = WRITER.split("int ensure_randomized_cdhash_for_slice(", 1)[1]
        self.assertLess(writer.index("rh3_code_directory_pages_match(macho, bestCDBlob)"),
                        writer.index("fat_init_for_writing(inputPath)"))
        existing = WRITER.split("static int rh3_existing_branded_cdhash(", 1)[1].split(
            "int ensure_randomized_cdhash_for_slice(", 1)[0]
        self.assertIn("rh3_code_directory_pages_match(macho, best)", existing)

    def test_compiled_native_gate_rejects_corrupted_later_page(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("Host C compiler unavailable")
        source = WRITER.split("bool rh3_code_directory_pages_match(", 1)[1].split(
            "// The brand lives inside page 0.", 1)[0]
        function = "bool rh3_code_directory_pages_match(" + source
        prefix = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define CC_SHA384_DIGEST_LENGTH 48
#define CODE_DIRECTORY_APPLY_BYTE_ORDER(cd, how) ((void)0)
#define BIG_TO_HOST_APPLIER 0
typedef struct { uint64_t size; } Slice;
typedef struct { Slice archDescriptor; unsigned char data[8192]; } MachO;
typedef struct {
    uint32_t codeLimit, hashOffset, length, nCodeSlots;
    uint8_t hashSize, pageSize;
} CS_CodeDirectory;
typedef struct { unsigned char blob[256]; size_t size; } CS_DecodedBlob;
static int csd_blob_read(CS_DecodedBlob *blob, size_t off, size_t len, void *out) {
    if (off > blob->size || len > blob->size-off) return -1;
    memcpy(out, blob->blob+off, len);
    return 0;
}
static bool code_directory_calculate_page_hash(CS_CodeDirectory *cd, MachO *m,
                                                int slot, uint8_t *output) {
    if (slot < 0 || (uint32_t)slot >= cd->nCodeSlots) return false;
    for (unsigned i=0;i<cd->hashSize;i++)
        output[i] = m->data[(size_t)slot*4096+i];
    return true;
}
"""
        suffix = r"""
int main(void) {
    MachO m={0};
    m.archDescriptor.size=8192;
    CS_DecodedBlob b={0};
    CS_CodeDirectory cd={8192, sizeof(cd), sizeof(cd)+40, 2, 20, 12};
    b.size=cd.length;
    for (unsigned i=0;i<8192;i++) m.data[i]=(unsigned char)(i/4096*55 + i%131);
    memcpy(b.blob,&cd,sizeof(cd));
    for (unsigned page=0;page<2;page++)
        memcpy(b.blob+cd.hashOffset+page*20,m.data+page*4096,20);
    if(!rh3_code_directory_pages_match(&m,&b)) return 1;
    m.data[4096]^=1;
    if(rh3_code_directory_pages_match(&m,&b)) return 2;
    m.data[4096]^=1;
    m.data[0]^=1;
    if(rh3_code_directory_pages_match(&m,&b)) return 3;
    m.data[0]^=1;
    cd.codeLimit=8193; memcpy(b.blob,&cd,sizeof(cd));
    if(rh3_code_directory_pages_match(&m,&b)) return 4;
    cd.codeLimit=8192;cd.hashOffset=250;memcpy(b.blob,&cd,sizeof(cd));
    if(rh3_code_directory_pages_match(&m,&b)) return 5;
    cd.hashOffset=sizeof(cd);cd.nCodeSlots=0;memcpy(b.blob,&cd,sizeof(cd));
    if(rh3_code_directory_pages_match(&m,&b)) return 6;
    cd.nCodeSlots=2;cd.pageSize=25;memcpy(b.blob,&cd,sizeof(cd));
    if(rh3_code_directory_pages_match(&m,&b)) return 7;
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory) / "signed_pages.c"
            exe = Path(directory) / "signed_pages.exe"
            src.write_text(prefix + function + suffix, encoding="utf-8")
            result = subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                     str(src), "-o", str(exe)], capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr + f" exit={run.returncode}")


if __name__ == "__main__":
    unittest.main()
