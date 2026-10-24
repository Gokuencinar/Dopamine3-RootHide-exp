"""Regressions for avoiding unnecessary O_RDWR of running Mach-O files.

The source-order and error contract is verified here on Windows. Xcode's
native build must additionally compile the real ChOma call path. Device
runtime and EBADMACHO timing require separate physical evidence.
"""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

SRC = (Path(__file__).resolve().parents[2] /
       "BaseBin/libjailbreak/src/roothider/recdhash.m")


class ReadonlyCdhashTests(unittest.TestCase):
    def test_both_paths_reject_unbounded_or_malformed_signatures_before_decode(self):
        source = SRC.read_text(encoding="utf-8")
        self.assertIn('#include "signature_validation.h"', source)
        guard = source.split("static CS_SuperBlob *rh3_verified_code_signature(", 1)[1].split(
            "static int rh3_existing_branded_cdhash(", 1)[0]
        self.assertIn("macho_find_code_signature_bounds(", guard)
        self.assertIn("signatureSize > macho->archDescriptor.size - signatureOffset", guard)
        self.assertIn("rh3_signature_blob_is_well_formed(", guard)
        self.assertIn("free(superblob);", guard)
        self.assertEqual(source.count("rh3_verified_code_signature(macho);"), 2)
        self.assertNotIn("macho_read_code_signature(macho);", source.split(
            "static int rh3_existing_branded_cdhash(", 1)[1])
        signatures = (SRC.parent / "signatures.m").read_text(encoding="utf-8")
        self.assertIn('#include "signature_validation.h"', signatures)
        self.assertIn("bool rh3_signature_blob_is_well_formed(", signatures)
        self.assertNotIn("static bool rh3_signature_blob_is_well_formed(", signatures)

    def test_branded_fastpath_rejects_stale_page_zero_hash_without_rewriting(self):
        source = SRC.read_text(encoding="utf-8")
        fastpath = source.split("static bool rh3_branded_page_zero_hash_matches(", 1)[1].split(
            "int ensure_randomized_cdhash_for_slice(", 1)[0]
        self.assertIn("code_directory_calculate_page_hash(&codeDir, macho, 0, computedHash)", fastpath)
        self.assertIn("csd_blob_read(best, codeDir.hashOffset, codeDir.hashSize, storedHash)", fastpath)
        self.assertIn("memcmp(computedHash, storedHash, codeDir.hashSize) == 0", fastpath)
        self.assertLess(fastpath.index("memcmp(computedHash, storedHash, codeDir.hashSize) == 0"),
                        fastpath.index("csd_code_directory_calculate_hash(best, cdhashOut)"))
        self.assertIn("rh3_branded_page_zero_hash_matches(best, macho)", fastpath)
        self.assertNotIn("memory_stream_write", fastpath)

    def test_writer_fallback_never_accepts_partial_existing_brand(self):
        source = SRC.read_text(encoding="utf-8")
        writer = source.split("int ensure_randomized_cdhash_for_slice(", 1)[1]
        before_change = writer.split("*rd2 = jbinfo(jbrand);", 1)[0]
        self.assertIn("*rd2 == jbinfo(jbrand) && jbinfo(jbrand) != 0", before_change)
        self.assertIn("rh3_branded_page_zero_hash_matches(bestCDBlob, macho)", before_change)
        self.assertIn("break;", before_change)

    def test_native_page_zero_hash_matching_positive_and_negative(self):
        """Execute the production comparison code with mock ChOma data access."""
        compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not compiler:
            self.skipTest("C compiler unavailable")
        source = SRC.read_text(encoding="utf-8")
        start = source.index("static bool rh3_branded_page_zero_hash_matches(")
        end = source.index("static int rh3_existing_branded_cdhash(", start)
        helper = source[start:end]
        harness = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#define CC_SHA384_DIGEST_LENGTH 48
#define BIG_TO_HOST_APPLIER 0
#define CODE_DIRECTORY_APPLY_BYTE_ORDER(cd, a) do { \
    (cd)->nCodeSlots=__builtin_bswap32((cd)->nCodeSlots); \
    (cd)->hashOffset=__builtin_bswap32((cd)->hashOffset); \
} while(0)
typedef struct { uint32_t nCodeSlots, hashOffset; uint8_t hashSize; } CS_CodeDirectory;
typedef struct { unsigned char buffer[96]; int badRead; } CS_DecodedBlob;
typedef struct { unsigned char actual[48]; int badCalculation; } MachO;
static int csd_blob_read(CS_DecodedBlob *b, uint32_t off, size_t size, void *out) {
    if (b->badRead || off > sizeof(b->buffer) || size > sizeof(b->buffer)-off) return -1;
    memcpy(out, b->buffer+off, size); return 0;
}
static bool code_directory_calculate_page_hash(CS_CodeDirectory *cd, MachO *m,
                                                int slot, uint8_t *out) {
    if (slot || m->badCalculation) return false;
    memcpy(out, m->actual, cd->hashSize); return true;
}
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr,"case line %d: %s\n",__LINE__,#expr); return 1; } } while(0)
'''
        cases = r'''
int main(void) {
    CS_DecodedBlob blob={0}; MachO macho={0};
    CS_CodeDirectory cd={.nCodeSlots=__builtin_bswap32(1),
        .hashOffset=__builtin_bswap32(32), .hashSize=32};
    memcpy(blob.buffer,&cd,sizeof(cd));
    for (int i=0;i<32;i++) macho.actual[i]=(unsigned char)(i+1);
    memcpy(blob.buffer+32,macho.actual,32);
    CHECK(rh3_branded_page_zero_hash_matches(&blob,&macho));
    blob.buffer[32] ^= 0x10;
    CHECK(!rh3_branded_page_zero_hash_matches(&blob,&macho));
    blob.buffer[32] ^= 0x10;
    macho.badCalculation=1;
    CHECK(!rh3_branded_page_zero_hash_matches(&blob,&macho));
    macho.badCalculation=0; blob.badRead=1;
    CHECK(!rh3_branded_page_zero_hash_matches(&blob,&macho));
    blob.badRead=0; cd.nCodeSlots=__builtin_bswap32(0);
    memcpy(blob.buffer,&cd,sizeof(cd));
    CHECK(!rh3_branded_page_zero_hash_matches(&blob,&macho));
    cd.nCodeSlots=__builtin_bswap32(1); cd.hashSize=49;
    memcpy(blob.buffer,&cd,sizeof(cd));
    CHECK(!rh3_branded_page_zero_hash_matches(&blob,&macho));
    CHECK(!rh3_branded_page_zero_hash_matches(NULL,&macho));
    CHECK(!rh3_branded_page_zero_hash_matches(&blob,NULL));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "branded.c"
            exe = Path(directory) / "branded.exe"
            path.write_text(harness + helper + cases, encoding="utf-8")
            build = subprocess.run([compiler, "-std=c11", str(path), "-o", str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(exe)], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_fastpath_precedes_every_write_open(self):
        source = SRC.read_text(encoding="utf-8")
        entry = source.split("int ensure_randomized_cdhash_for_slice(", 1)[1]
        self.assertRegex(entry, re.compile(
            r"int existing = rh3_existing_branded_cdhash\(inputPath, offset, cdhashOut\);"
            r"\s*if \(existing != 0\) return existing > 0 \? 0 : -1;"
        ))
        # r198 library recovery now validates the unmodified CodeDirectory
        # before opening writable. The original contract (fastpath first,
        # no writable open for a known brand) must remain true.
        self.assertLess(entry.index("int existing = rh3_existing_branded_cdhash("),
                        entry.index("fat_init_from_path(inputPath)"))
        self.assertLess(entry.index("fat_init_from_path(inputPath)"),
                        entry.index("fat_init_for_writing(inputPath)"))
        self.assertLess(entry.index("memcmp(pageHash, oldHash, codeDir.hashSize)"),
                        entry.index("fat_init_for_writing(inputPath)"))
        self.assertLess(entry.index("fat_init_for_writing(inputPath)"),
                        entry.index("if (!unchanged)"))

    def test_existing_brand_uses_only_readonly_choma_and_validates_code_directory(self):
        source = SRC.read_text(encoding="utf-8")
        helper = source.split("static int rh3_existing_branded_cdhash(", 1)[1].split(
            "int ensure_randomized_cdhash_for_slice(", 1)[0]
        self.assertIn("fat_init_from_path(inputPath)", helper)
        self.assertIn("if (activeBrand == 0) return 0;", helper)
        self.assertNotIn("fat_init_for_writing", helper)
        self.assertNotIn("memory_stream_write", helper)
        self.assertIn("requestedOffset == (uint64_t)-1", helper)
        self.assertIn("fat_find_slice_by_offset(fat, requestedOffset)", helper)
        self.assertIn("command.cmdsize >= sizeof(struct segment_command_64) + sizeof(struct section_64)", helper)
        self.assertIn("storedBrand == activeBrand", helper)
        self.assertIn("if (!branded) { fat_free(fat); return 0; }", helper)
        self.assertIn("csd_superblob_find_best_code_directory(decoded)", helper)
        self.assertIn("csd_code_directory_calculate_hash(best, cdhashOut)", helper)
        self.assertIn("return result == 0 ? 1 : -1;", helper)

    def test_no_rewrite_on_corrupt_branded_signature_and_fd_cleanup(self):
        text = SRC.read_text(encoding="utf-8")
        helper = text.split("static int rh3_existing_branded_cdhash(", 1)[1].split(
            "int ensure_randomized_cdhash_for_slice(", 1)[0]
        self.assertIn("if (!superblob) { fat_free(fat); return -1; }", helper)
        self.assertIn("if (decoded) csd_superblob_free(decoded);", helper)
        self.assertIn("free(superblob);", helper)
        self.assertIn("fat_free(fat);", helper)


if __name__ == "__main__":
    unittest.main()
