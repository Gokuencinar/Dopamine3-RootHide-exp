"""RootHide bootstrap extraction must not report success after skipped entries."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class BootstrapArchiveWarningContract(unittest.TestCase):
    def test_nonfatal_libarchive_warning_is_fatal_for_pinned_bootstrap(self):
        content = (ROOT / "BaseBin/libjailbreak/src/util.c").read_text(encoding="utf-8")
        extractor = content.split("int libarchive_unarchive(", 1)[1].split(
            "// code from ktrw", 1
        )[0]
        self.assertNotIn("r < ARCHIVE_WARN", extractor)
        self.assertIn("if (r < ARCHIVE_OK) {\n\t\t\t\t\tfprintf", extractor)
        self.assertIn("archive_write_header(ext, entry);", extractor)
        self.assertIn("archive_write_finish_entry(ext);", extractor)
        self.assertIn("return 1;", extractor)


if __name__ == "__main__":
    unittest.main()
