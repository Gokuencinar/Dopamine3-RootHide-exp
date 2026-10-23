"""Regressions for avoiding unnecessary O_RDWR of running Mach-O files.

The source-order and error contract is verified here on Windows. Xcode's
native build must additionally compile the real ChOma call path. Device
runtime and EBADMACHO timing require separate physical evidence.
"""

from pathlib import Path
import re
import unittest

SRC = (Path(__file__).resolve().parents[2] /
       "BaseBin/libjailbreak/src/roothider/recdhash.m")


class ReadonlyCdhashTests(unittest.TestCase):
    def test_fastpath_precedes_every_write_open(self):
        source = SRC.read_text(encoding="utf-8")
        entry = source.split("int ensure_randomized_cdhash_for_slice(", 1)[1]
        self.assertRegex(entry, re.compile(
            r"int existing = rh3_existing_branded_cdhash\(inputPath, offset, cdhashOut\);"
            r"\s*if \(existing != 0\) return existing > 0 \? 0 : -1;"
            r"\s*Fat\* fat = fat_init_for_writing\(inputPath\);"
        ))

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
