"""Regression gate for the physical r198 APT Mach-O signature failure.

The failure must not leave a library partially rebranded when its CodeDirectory
cannot be committed. These source checks apply to the native iOS writer; they
are deliberately independent of the iOS SDK and device access.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "BaseBin/libjailbreak/src/roothider/recdhash.m"


class AptSignatureTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = SOURCE.read_text(encoding="utf-8")
        cls.writer = source[source.index("int ensure_randomized_cdhash_for_slice("):]

    def test_preflight_page_slot_and_linkedit_bounds_before_write(self):
        writer = self.writer
        first_write = writer.index("memory_stream_write(fat->stream")
        preflight = writer[:first_write]
        self.assertIn("firstPageSize", preflight)
        self.assertIn("firstsectoffset", preflight)
        self.assertIn("codeDir.hashOffset", preflight)
        self.assertIn("linkedit.datasize", preflight)
        self.assertIn("oldHash", preflight)

    def test_written_section_and_hash_are_rolled_back_on_failure(self):
        writer = self.writer
        self.assertIn("struct section_64 originalSection = firstsection;", writer)
        self.assertIn("if (retval != 0)", writer)
        failure = writer[writer.index("if (retval != 0)"):]
        self.assertIn("memory_stream_write(fat->stream, sectionOffset", failure)
        self.assertIn("memory_stream_write(fat->stream, hashOffset", failure)
        self.assertIn("oldHash", failure)
        self.assertIn("originalSection", failure)

    def test_avoid_rebranding_changed_macho_between_read_and_write(self):
        writer = self.writer
        self.assertIn("observedSignature", writer)
        self.assertIn("observedSection", writer)
        self.assertIn("unchanged", writer)
        self.assertIn("fat_init_for_writing(inputPath)", writer)
        self.assertLess(writer.index("if (!unchanged)"), writer.index("*rd2 = jbinfo(jbrand)"))


if __name__ == "__main__":
    unittest.main()
