"""Trust recursion must reject allocation failures without crashing launchd."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


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


if __name__ == "__main__":
    unittest.main()
