"""Regressions for trustcache pages and allocations.

Source contracts are checked against production code; the portable model
exercises the boundary cases independently. No kernel writes are performed.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "BaseBin/libjailbreak/src/trustcache.c").read_text(encoding="utf-8")


class TrustcachePagingTests(unittest.TestCase):
    def test_actual_insert_loop_advances_source_cursor_between_pages(self):
        section = SRC.split("int jb_trustcache_add_entries(", 1)[1].split(
            "int jb_trustcache_add_cdhashes(", 1
        )[0]
        self.assertIn("uint32_t insertedEntryCount = 0;", section)
        self.assertRegex(section, r"entries\[insertedEntryCount\s*\+\s*i\]")
        self.assertNotRegex(section, r"=\s*entries\[i\]\s*;")
        self.assertIn("insertedEntryCount += entryCountToInsert;", section)
        self.assertIn("remainingEntryCount -= entryCountToInsert;", section)
        self.assertLess(section.index("remainingEntryCount -= entryCountToInsert;"),
                        section.index("insertedEntryCount += entryCountToInsert;"))
        self.assertIn("if (freeJbTcKaddr == 0) return -1;", section)
        self.assertIn("entryCount > 0 && !entries", section)

    def test_batch_spanning_partially_filled_and_multiple_new_pages(self):
        # The production algorithm's cursor invariants, with small pages:
        # first a partially filled page, then full and partial new pages.
        capacity = 3
        existing = [("old", 0), ("old", 1)]
        source = list(range(9))
        pages = [existing]
        inserted = 0
        remaining = len(source)
        while remaining:
            page = next((page for page in pages if len(page) < capacity), None)
            if page is None:
                page = []
                pages.append(page)
            take = min(remaining, capacity - len(page))
            page.extend(source[inserted:inserted + take])
            inserted += take
            remaining -= take
        self.assertEqual(inserted, 9)
        self.assertEqual(pages, [[("old", 0), ("old", 1), 0],
                                 [1, 2, 3], [4, 5, 6], [7, 8]])
        self.assertEqual([x for page in pages for x in page if isinstance(x, int)], source)

    def test_cdhash_wrapper_uses_bounded_stack_and_reports_alloc_failure(self):
        section = SRC.split("int jb_trustcache_add_cdhashes(", 1)[1].split(
            "int jb_trustcache_add_entry(", 1
        )[0]
        self.assertNotIn("entries[hashCount]", section)
        self.assertRegex(section, r"\bcalloc\(hashCount,\s*sizeof\(\*entries\)\)")
        self.assertIn("if (!entries) return -1;", section)
        self.assertIn("free(entries);", section)
        self.assertIn("return result;", section)
        self.assertIn("hashCount == 0", section)
        self.assertIn("SIZE_MAX / sizeof(trustcache_entry_v1)", section)


if __name__ == "__main__":
    unittest.main()
