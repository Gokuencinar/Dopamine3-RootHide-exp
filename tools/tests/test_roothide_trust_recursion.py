"""Trust recursion must reject allocation failures without crashing launchd."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
SIGNATURES = ROOT / "BaseBin/libjailbreak/src/roothider/signatures.m"


def signatures_source():
    return SIGNATURES.read_text(encoding="utf-8")


class RootHideTrustRecursionTests(unittest.TestCase):
    def test_allocation_is_checked_before_overwriting_output(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/signatures.m").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("*cdhashesOut = realloc", source)
        self.assertIn("cdhash_t *resized = realloc(", source)
        self.assertIn("if (!resized) {", source)
        self.assertLess(source.index("if (!resized) {"), source.index("*cdhashesOut = resized;"))
        self.assertIn("*cdhashCountOut = newCount;", source)

    def test_recursive_failure_returns_error_and_skips_trustcache_upload(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/signatures.m").read_text(
            encoding="utf-8"
        )
        caller = (
            ROOT / "BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c"
        ).read_text(encoding="utf-8")
        self.assertIn("RH3_MAX_TRUST_DEPENDENCIES 4096", source)
        self.assertIn("RH3_MAX_TRUST_DEPTH 64", source)
        self.assertIn("return failed ? -1 : 0;", source)
        self.assertIn("if (recurse_collect_untrusted_cdhashes(", caller)
        self.assertLess(caller.index("return -1;", caller.index("if (recurse_collect_untrusted_cdhashes(")), caller.index("jb_trustcache_add_cdhashes(cdhashes, cdhashesCount)"))

    def test_missing_required_dependencies_propagate_but_weak_can_be_absent(self):
        source = signatures_source()
        self.assertIn("unsigned depth, bool required, bool *failed)", source)
        self.assertIn("if (required) *failed = true;", source)
        self.assertIn("cmd != LC_LOAD_WEAK_DYLIB && cmd != LC_LAZY_LOAD_DYLIB", source)
        self.assertIn("depth + 1, dependencyRequired, failed)", source)
        self.assertIn("0, true, &failed)", source)
        self.assertIn('JBLogError("Failed to decode code signature', source)
        self.assertIn('JBLogError("Failed to calculate CDHash', source)
        self.assertIn("*failed = true;", source[source.index("ensure_randomized_cdhash_for_slice("):])

    def test_unreadable_macho_signature_is_not_treated_as_non_adhoc(self):
        source = signatures_source()
        start = source.index("uint32_t signatureOffset = 0, signatureSize = 0;")
        stop = source.index("// Recurse this block on all dependencies", start)
        block = source[start:stop]
        self.assertIn("macho_find_code_signature_bounds(macho, &signatureOffset, &signatureSize)", block)
        self.assertIn("signatureSize > macho->archDescriptor.size - signatureOffset", block)
        self.assertIn("if (!superblob) {", block)
        self.assertIn('JBLogError("Missing or unreadable code signature', block)
        self.assertIn('JBLogError("Malformed or missing CodeDirectory', block)
        self.assertIn("*failed = true;", block)
        self.assertIn("if (*failed || !isAdhocSigned) {", block)
        self.assertLess(block.index("if (*failed || !isAdhocSigned)"), block.index("fat_free(fat);", block.index("if (*failed || !isAdhocSigned)")))

    def test_valid_non_adhoc_requires_readable_code_directory_but_is_not_rehashed(self):
        source = signatures_source()
        block = source[source.index("uint32_t signatureOffset = 0, signatureSize = 0;"):
                       source.index("// Recurse this block on all dependencies")]
        self.assertLess(block.index("rh3_signature_blob_is_well_formed"), block.index("csd_superblob_decode"))
        self.assertLess(block.index("csd_superblob_calculate_best_cdhash"),
                        block.index("isAdhocSigned = csd_superblob_is_adhoc_signed"))
        self.assertIn("if (isAdhocSigned && !cdhashesContains(cdhash) &&", block)
        self.assertIn("!is_cdhash_trustcached(cdhash)", block)
        self.assertNotIn("cdhashWasKnown", block)
        self.assertIn("if (*failed || !isAdhocSigned)", block)

    def test_duplicate_or_trustcached_adhoc_cdhash_does_not_skip_new_dependencies(self):
        source = signatures_source()
        block = source[source.index("// A signed Mach-O must contain a readable SuperBlob"):
                       source.index("fat_free(fat);", source.index("// Recurse this block on all dependencies"))]
        self.assertNotIn("cdhashWasKnown", block)
        self.assertIn("!cdhashesContains(cdhash)", block)
        self.assertIn("!is_cdhash_trustcached(cdhash)", block)
        self.assertIn("macho_enumerate_dependencies(macho", block)

    def test_signature_bounds_validator_with_real_c_execution(self):
        """Compile the actual extracted C helper against test-only ChOma types.

        The harness exercises the production helper, not a Python reimplementation.
        It intentionally avoids requiring an iOS SDK or an Objective-C runtime.
        """
        compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not compiler:
            self.skipTest("C compiler unavailable (source contract tests still run)")
        source = signatures_source()
        # Shared with recdhash's read-only branded fastpath: the validator is
        # intentionally exported, rather than a signatures.m-local static.
        start = source.index("bool rh3_signature_blob_is_well_formed(")
        end = source.index("NSString* resolveLoaderExecutablePaths", start)
        helper = source[start:end]
        harness = textwrap.dedent(r"""
            #include <stdint.h>
            #include <stdbool.h>
            #include <stddef.h>
            #include <string.h>
            #include <stdio.h>
            #include <stdlib.h>
            #define BIG_TO_HOST(v) __builtin_bswap32(v)
            #define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0U
            #define CSMAGIC_DETACHED_SIGNATURE 0xfade0cc1U
            #define CSMAGIC_CODEDIRECTORY 0xfade0c02U
            #define CSMAGIC_BLOBWRAPPER 0xfade0b01U
            #define CSSLOT_CODEDIRECTORY 0U
            #define CSSLOT_REQUIREMENTS 2U
            #define CSSLOT_ALTERNATE_CODEDIRECTORIES 0x1000U
            #define CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT 0x1005U
            #define CSSLOT_SIGNATURESLOT 0x10000U
            #define CS_HASHTYPE_SHA160_160 1U
            #define CS_HASHTYPE_SHA256_256 2U
            #define CS_HASHTYPE_SHA256_160 3U
            #define CS_HASHTYPE_SHA384_384 4U
            typedef struct { uint32_t type, offset; } CS_BlobIndex;
            typedef struct { uint32_t magic, length, count; CS_BlobIndex index[]; } CS_SuperBlob;
            typedef struct { uint32_t magic, length; char data[]; } CS_GenericBlob;
            typedef struct {
                uint32_t magic, length, version, flags, hashOffset, identOffset;
                uint32_t nSpecialSlots, nCodeSlots, codeLimit;
                uint8_t hashSize, hashType, platform, pageSize;
                uint32_t spare2, scatterOffset, teamOffset;
            } CS_CodeDirectory;
            static void write_be32(void *dst, uint32_t n) {
                n = __builtin_bswap32(n); memcpy(dst, &n, sizeof(n));
            }
            #define CHECK(expr) do { if (!(expr)) { \
                fprintf(stderr, "failed line %d: %s\n", __LINE__, #expr); return 1; \
            } } while(0)
        """)
        cases = textwrap.dedent(r"""
            int main(void) {
                uint8_t bytes[256] = {0};
                CS_SuperBlob *blob = (CS_SuperBlob *)bytes;
                size_t directory_offset = sizeof(CS_SuperBlob) + 2*sizeof(CS_BlobIndex);
                size_t directory_size = sizeof(CS_CodeDirectory) + 8 + 32;
                size_t wrapper_offset = directory_offset + directory_size;
                size_t total_size = wrapper_offset + 16;
                write_be32(&blob->magic, CSMAGIC_EMBEDDED_SIGNATURE);
                write_be32(&blob->length, (uint32_t)total_size);
                write_be32(&blob->count, 2);
                write_be32(&blob->index[0].type, CSSLOT_CODEDIRECTORY);
                write_be32(&blob->index[0].offset, (uint32_t)directory_offset);
                write_be32(&blob->index[1].type, CSSLOT_SIGNATURESLOT);
                write_be32(&blob->index[1].offset, (uint32_t)wrapper_offset);
                CS_CodeDirectory *directory = (CS_CodeDirectory *)(bytes + directory_offset);
                write_be32(&directory->magic, CSMAGIC_CODEDIRECTORY);
                write_be32(&directory->length, (uint32_t)directory_size);
                write_be32(&directory->version, 0x20200);
                write_be32(&directory->hashOffset, sizeof(CS_CodeDirectory) + 8);
                write_be32(&directory->identOffset, sizeof(CS_CodeDirectory));
                write_be32(&directory->nCodeSlots, 1);
                memcpy(bytes + directory_offset + sizeof(CS_CodeDirectory), "test", 5);
                directory->hashType = CS_HASHTYPE_SHA256_256;
                directory->hashSize = 32;
                directory->pageSize = 12;
                write_be32(&directory->codeLimit, 1);
                CS_GenericBlob *wrapper = (CS_GenericBlob *)(bytes + wrapper_offset);
                write_be32(&wrapper->magic, CSMAGIC_BLOBWRAPPER);
                write_be32(&wrapper->length, 16);

                CHECK(rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                directory->pageSize = 20;
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                directory->pageSize = 255;
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                directory->pageSize = 0;
                CHECK(rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                directory->pageSize = 14;
                CHECK(rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                directory->pageSize = 12;
                write_be32(&directory->codeLimit, 4097);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                write_be32(&directory->codeLimit, 0);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                write_be32(&directory->codeLimit, 1);
                // A structurally valid ad-hoc signature may have no CMS slot.
                write_be32(&blob->count, 1);
                write_be32(&blob->length, (uint32_t)wrapper_offset);
                CHECK(rh3_signature_blob_is_well_formed(blob, (uint32_t)wrapper_offset));
                write_be32(&blob->length, (uint32_t)total_size);
                write_be32(&blob->count, 2);
                CHECK(!rh3_signature_blob_is_well_formed(NULL, (uint32_t)total_size));
                CHECK(!rh3_signature_blob_is_well_formed(blob, 8));
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size - 1));
                write_be32(&blob->count, UINT32_MAX);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                write_be32(&blob->count, 2);
                write_be32(&blob->index[0].offset, 4);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                write_be32(&blob->index[0].offset, (uint32_t)directory_offset);
                write_be32(&directory->length, 0xFFFFFFF0U);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                write_be32(&directory->length, (uint32_t)directory_size);
                write_be32(&directory->magic, CSMAGIC_BLOBWRAPPER);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                write_be32(&directory->magic, CSMAGIC_CODEDIRECTORY);
                directory->hashSize = 10;
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                directory->hashSize = 32;
                write_be32(&directory->nCodeSlots, UINT32_MAX);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                write_be32(&directory->nCodeSlots, 1);
                write_be32(&directory->identOffset, (uint32_t)directory_size + 1);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                write_be32(&directory->identOffset, sizeof(CS_CodeDirectory));
                memset(bytes + directory_offset + sizeof(CS_CodeDirectory), 'X', 8);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                memcpy(bytes + directory_offset + sizeof(CS_CodeDirectory), "test", 5);
                write_be32(&directory->hashOffset, UINT32_MAX);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                write_be32(&directory->hashOffset, sizeof(CS_CodeDirectory) + 8);
                write_be32(&wrapper->magic, CSMAGIC_CODEDIRECTORY);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                write_be32(&wrapper->magic, CSMAGIC_BLOBWRAPPER);
                write_be32(&blob->index[0].type, CSSLOT_REQUIREMENTS);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                write_be32(&blob->index[0].type, CSSLOT_CODEDIRECTORY);
                write_be32(&blob->magic, 0x01020304);
                CHECK(!rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                write_be32(&blob->magic, CSMAGIC_EMBEDDED_SIGNATURE);
                CHECK(rh3_signature_blob_is_well_formed(blob, (uint32_t)total_size));
                // A CMS wrapper with payload is accepted structurally, not
                // claimed to be cryptographically authenticated.
                return 0;
            }
        """)
        harness += helper + cases
        with tempfile.TemporaryDirectory() as tmp:
            c_file = Path(tmp) / "signature_contract.c"
            executable = Path(tmp) / "signature_contract.exe"
            c_file.write_text(harness, encoding="utf-8")
            build = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                    str(c_file), "-o", str(executable)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            check = subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stderr)


if __name__ == "__main__":
    unittest.main()
